use base64::prelude::{BASE64_STANDARD, Engine};
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

type Point = RistrettoPoint;

fn nonidentity(p: Point) -> Result<Point, String> {
    if p == Point::identity() {
        Err("A curve point is trivial, breaking the protocol.".into())
    } else {
        Ok(p)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub mine: u32,
    pub theirs: u32,
    pub matches: Vec<bool>,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum Reply {
    Msg1 { msg1: String },
    Items { items: Vec<String> },
    Msg2 { msg2: String },
    AliceDone { outcome: Outcome, msg3: String },
    BobDone { outcome: Outcome },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Request {
    AliceStart {
        seed: String,
        choices: Vec<bool>,
        items: Vec<String>,
    },
    ReadList {
        msg1: String,
    },
    BobRespond {
        seed: String,
        choices: Vec<bool>,
        msg1: String,
    },
    AliceFinish {
        seed: String,
        choices: Vec<bool>,
        items: Vec<String>,
        msg2: String,
    },
    BobFinish {
        seed: String,
        choices: Vec<bool>,
        msg1: String,
        msg3: String,
    },
}

use std::cell::RefCell;

thread_local! {
    static INPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

#[mutants::skip]
#[unsafe(no_mangle)]
pub extern "C" fn kiss_input(len: usize) -> *mut u8 {
    INPUT.with_borrow_mut(|input| {
        input.clear();
        input.resize(len, 0);
        input.as_mut_ptr()
    })
}

#[mutants::skip]
#[unsafe(no_mangle)]
pub extern "C" fn kiss_call() {
    let reply = INPUT.with_borrow(|input| {
        if let Ok(request) = serde_json::from_slice::<Request>(input) {
            serde_json::to_string(&handle(request)).expect("to serialize without error~")
        } else {
            "What kind of bogus input is this?".to_string()
        }
    });
    OUTPUT.set(reply.into_bytes());
}

#[mutants::skip]
#[unsafe(no_mangle)]
pub extern "C" fn kiss_output() -> *const u8 {
    OUTPUT.with_borrow(|output| output.as_ptr())
}

#[mutants::skip]
#[unsafe(no_mangle)]
pub extern "C" fn kiss_output_len() -> usize {
    OUTPUT.with_borrow(|output| output.len())
}

pub fn handle(request: Request) -> Result<Reply, String> {
    use Request::*;

    let reply = match request {
        AliceStart {
            seed,
            choices,
            items,
        } => {
            let seed = decode_seed(&seed);
            let msg1 = alice_start(&items, &choices, &seed)?;
            Reply::Msg1 {
                msg1: BASE64_STANDARD.encode(&msg1),
            }
        }
        ReadList { msg1 } => {
            let items = read_list(
                &BASE64_STANDARD
                    .decode(&msg1)
                    .map_err(|_| "Could not read msg1 as base64".to_string())?,
            )?;
            Reply::Items { items }
        }
        BobRespond {
            seed,
            choices,
            msg1,
        } => {
            let seed = decode_seed(&seed);
            let msg2 = bob_respond(
                &choices,
                &seed,
                &BASE64_STANDARD
                    .decode(&msg1)
                    .map_err(|_| "Could not read msg2 as base64".to_string())?,
            )?;
            Reply::Msg2 {
                msg2: BASE64_STANDARD.encode(&msg2),
            }
        }
        AliceFinish {
            seed,
            choices,
            items,
            msg2,
        } => {
            let seed = decode_seed(&seed);
            let (outcome, msg3) = alice_finish(
                &items,
                &choices,
                &seed,
                &BASE64_STANDARD
                    .decode(&msg2)
                    .map_err(|_| "Could not read msg2 as base64".to_string())?,
            )?;
            Reply::AliceDone {
                outcome,
                msg3: BASE64_STANDARD.encode(&msg3),
            }
        }
        BobFinish {
            seed,
            choices,
            msg1,
            msg3,
        } => {
            let seed = decode_seed(&seed);
            let outcome = bob_finish(
                &choices,
                &seed,
                &BASE64_STANDARD
                    .decode(&msg1)
                    .map_err(|_| "Could not read msg1 as base64".to_string())?,
                &BASE64_STANDARD
                    .decode(&msg3)
                    .map_err(|_| "Could not read msg3 as base64".to_string())?,
            )?;
            Reply::BobDone { outcome }
        }
    };

    Ok(reply)
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct AliceState {
    ctx: Context,
    ballot: OwnBallot,
    dh_secret: Scalar,
    h1: [u8; 64],
    msg1: Vec<u8>,
}

fn hash_to_point(context: &[u8], label: &[u8], index: u64) -> Point {
    let mut t = transcript(b"hash-to-point");
    put(&mut t, b"context", context);
    put(&mut t, b"label", label);
    put_u64(&mut t, b"index", index);
    Point::from_uniform_bytes(&Sha512::digest(&t).into())
}

fn put(t: &mut Vec<u8>, label: &[u8], data: &[u8]) {
    t.extend_from_slice(&(label.len() as u64).to_le_bytes());
    t.extend_from_slice(label);
    t.extend_from_slice(&(data.len() as u64).to_le_bytes());
    t.extend_from_slice(data);
}

fn put_statement(t: &mut Vec<u8>, b: &BallotStatement) {
    let xs: Vec<Point> = b.items.iter().map(|s| s.cell.x).collect();
    let cs: Vec<Point> = b.items.iter().map(|s| s.cell.c).collect();
    put_point(t, b"key", &b.key);
    put_points(t, b"x", &xs);
    put_points(t, b"c", &cs);
}

fn put_u64(t: &mut Vec<u8>, label: &[u8], n: u64) {
    put(t, label, &n.to_le_bytes());
}

fn put_point(t: &mut Vec<u8>, label: &[u8], p: &Point) {
    put(t, label, &p.compress().to_bytes());
}

fn put_points(t: &mut Vec<u8>, label: &[u8], ps: &[Point]) {
    put_u64(t, label, ps.len() as u64);
    for p in ps {
        put_point(t, label, p);
    }
}

fn transcript(label: &[u8]) -> Vec<u8> {
    let mut t = Vec::new();
    put(&mut t, b"protocol", b"kiss/v1");
    put(&mut t, b"label", label);
    t
}

fn message_digest<T: Serialize>(label: &[u8], value: &T) -> [u8; 64] {
    let mut t = transcript(label);
    put(
        &mut t,
        b"data",
        &serde_json::to_vec(value).expect("messages to serialize correctly"),
    );
    Sha512::digest(&t).into()
}

fn msg1_transcript(ctx: &Context, dh: &Point) -> Vec<u8> {
    let mut t = transcript(b"msg1-ballot");
    put(&mut t, b"sid", &ctx.sid);
    put(&mut t, b"list", &ctx.list_hash());
    put_point(&mut t, b"dh", dh);
    t
}

fn msg2_transcript(h1: &[u8; 64], dh: &Point) -> Vec<u8> {
    let mut t = transcript(b"msg2-ballot");
    put(&mut t, b"msg1", h1);
    put_point(&mut t, b"dh", dh);
    t
}

fn alice_state(items: &[String], choices: &[bool], seed: &[u8; 32]) -> Result<AliceState, String> {
    if choices.len() != items.len() {
        return Err("The number of answers does not match the number of items.".into());
    }
    let rng = Secrets::new(seed);
    let mut sid = [0u8; 16];
    sid.copy_from_slice(&rng.bytes(b"sid", 0)[..16]);
    let ctx = Context {
        sid,
        items: items.to_vec(),
    };
    let dh_secret = rng.nonzero_scalar(b"dh")?;
    let dh = RISTRETTO_BASEPOINT_POINT * dh_secret;
    let (ballot, proof) = prove_own_ballot(
        &rng,
        &ctx,
        Participant::Alice,
        choices,
        &msg1_transcript(&ctx, &dh),
    )?;
    let entries = ctx
        .items
        .iter()
        .zip(&ballot.cells)
        .map(|(item, cell)| Entry {
            item: item.clone(),
            cell: *cell,
        })
        .collect();
    let wire = Msg1Wire {
        sid,
        entries,
        key: ballot.key,
        dh,
        proof,
    };
    Ok(AliceState {
        h1: message_digest(b"msg1", &wire),
        msg1: serde_json::to_vec(&wire).expect("message to serialize"),
        ctx,
        ballot,
        dh_secret,
    })
}

fn bob_state(choices: &[bool], seed: &[u8; 32], msg1: &[u8]) -> Result<BobState, String> {
    let m1 = parse_msg1(msg1)?;
    let cells = m1.cells();
    if choices.len() != cells.len() {
        return Err("The number of answers does not match the number of items.".into());
    }
    let h1 = message_digest(b"msg1", &m1);
    let mut bind = transcript(b"bob-seed");
    put(&mut bind, b"msg1", &h1);
    let rng = Secrets::new(seed).bind(&bind);

    let ctx = m1.context();
    let dh_secret = rng.nonzero_scalar(b"dh")?;
    let dh = RISTRETTO_BASEPOINT_POINT * dh_secret;
    let (ballot, proof) = prove_own_ballot(
        &rng,
        &ctx,
        Participant::Bob,
        choices,
        &msg2_transcript(&h1, &dh),
    )?;
    let clear = ClearBallot {
        key: ballot.key,
        dh,
        cells: ballot.cells.clone(),
        proof,
    };
    let h2_clear = message_digest(b"msg2-clear", &clear);

    let (key_ba, key_ab) = session_keys(&h1, &h2_clear, &(m1.dh * dh_secret));
    let env = Envelope {
        key: &key_ba,
        label: b"msg2-dleq",
        h1: &h1,
        h2: &h2_clear,
    };
    let sealed = make_payload(&env, &ballot, &cells, &rng);
    let wire = Msg2Wire { clear, sealed };
    Ok(BobState {
        h1,
        h2: message_digest(b"msg2", &wire),
        msg2: serde_json::to_vec(&wire).expect("msg2 to encode correctly"),
        alice: m1,
        ballot,
        key_ab,
    })
}

fn session_keys(h1: &[u8; 64], h2_clear: &[u8; 64], shared: &Point) -> ([u8; 32], [u8; 32]) {
    let mut t = transcript(b"session-keys");
    put(&mut t, b"msg1", h1);
    put(&mut t, b"msg2-clear", h2_clear);
    put_point(&mut t, b"shared", shared);
    let d: [u8; 64] = Sha512::digest(&t).into();
    let mut ba = [0u8; 32];
    let mut ab = [0u8; 32];
    ba.copy_from_slice(&d[..32]);
    ab.copy_from_slice(&d[32..]);
    (ba, ab)
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct BallotWitness {
    secret: Scalar,
    openings: Vec<Opening>,
}

fn prove_own_ballot(
    rng: &Secrets,
    ctx: &Context,
    who: Participant,
    choices: &[bool],
    tr: &[u8],
) -> Result<(OwnBallot, BallotProof), String> {
    let ballot = make_ballot(rng, ctx, who, choices)?;
    let stmts = statements(ctx, who, &ballot.cells)?;
    let wit = BallotWitness {
        secret: ballot.secret,
        openings: ballot.openings.clone(),
    };
    let view = ballot_view(ctx, ballot.key, stmts);
    let proof = prove_ballot(tr, rng, &view, &wit);
    Ok((ballot, proof))
}

fn branches(s: &Statement, u: &Point) -> [(Point, Point); 2] {
    [(s.cell.x, s.cell.c - u), (s.cell.x - s.no_point, s.cell.c)]
}

fn simulate(
    b: &BallotStatement,
    s: &Statement,
    (x, c): &(Point, Point),
    br: &Branch,
) -> [Point; 3] {
    [
        RISTRETTO_BASEPOINT_POINT * br.s1 - b.key * br.challenge,
        s.base * br.s1 - x * br.challenge,
        b.v * br.s2 - c * br.challenge,
    ]
}

fn prove_ballot(
    tr: &[u8],
    secrets: &Secrets,
    b: &BallotStatement,
    w: &BallotWitness,
) -> BallotProof {
    let mut st = tr.to_vec();
    put_statement(&mut st, b);
    let rng = secrets.bind(&st);

    let mut commitments = Vec::with_capacity(2 * b.items.len());
    let mut pending = Vec::with_capacity(b.items.len());
    for (k, (s, o)) in b.items.iter().zip(&w.openings).enumerate() {
        let k = k as u64;
        let w1 = rng.scalar(b"ballot-w1", k);
        let w2 = rng.scalar(b"ballot-w2", k);
        let real_t = [RISTRETTO_BASEPOINT_POINT * w1, s.base * w1, b.v * w2];
        let fake = Branch {
            challenge: rng.scalar(b"ballot-fake-e", k),
            s1: rng.scalar(b"ballot-fake-s1", k),
            s2: rng.scalar(b"ballot-fake-s2", k),
        };
        let fake_branch = &branches(s, &b.u)[usize::from(o.choice)];
        let fake_t = simulate(b, s, fake_branch, &fake);
        let (yes_t, no_t) = if o.choice {
            (real_t, fake_t)
        } else {
            (fake_t, real_t)
        };
        commitments.push(yes_t);
        commitments.push(no_t);
        pending.push((w1, w2, fake));
    }

    let e = ballot_challenge(tr, b, &commitments);
    let items = pending
        .into_iter()
        .zip(&w.openings)
        .map(|((w1, w2, fake), o)| {
            let re = e - fake.challenge;
            let real = Branch {
                challenge: re,
                s1: w1 + re * w.secret,
                s2: w2 + re * o.randomness,
            };
            if o.choice {
                ItemProof {
                    yes: real,
                    no: fake,
                }
            } else {
                ItemProof {
                    yes: fake,
                    no: real,
                }
            }
        })
        .collect();
    BallotProof {
        challenge: e,
        items,
    }
}

fn ballot_challenge(tr: &[u8], b: &BallotStatement, commitments: &[[Point; 3]]) -> Scalar {
    let mut t = tr.to_vec();
    put_statement(&mut t, b);
    for c in commitments {
        put_points(&mut t, b"t", c);
    }
    challenge(&t, b"ballot")
}

fn challenge(t: &[u8], label: &[u8]) -> Scalar {
    let mut t = t.to_vec();
    put(&mut t, b"challenge", label);
    Scalar::from_bytes_mod_order_wide(&Sha512::digest(&t).into())
}

fn challenge_at(t: &[u8], label: &[u8], index: u64) -> Scalar {
    let mut t = t.to_vec();
    put(&mut t, b"challenge", label);
    put_u64(&mut t, b"index", index);
    Scalar::from_bytes_mod_order_wide(&Sha512::digest(&t).into())
}

struct BallotStatement {
    key: Point,
    u: Point,
    v: Point,
    items: Vec<Statement>,
}

fn ballot_view(ctx: &Context, key: Point, items: Vec<Statement>) -> BallotStatement {
    BallotStatement {
        key,
        u: ctx.u(),
        v: ctx.v(),
        items,
    }
}

fn make_ballot(
    rng: &Secrets,
    ctx: &Context,
    who: Participant,
    choices: &[bool],
) -> Result<OwnBallot, String> {
    let secret = rng.nonzero_scalar(b"exponent")?;
    let openings: Vec<Opening> = choices
        .iter()
        .enumerate()
        .map(|(k, &choice)| Opening {
            choice,
            randomness: rng.scalar(b"commit-r", k as u64),
        })
        .collect();
    let (u, v) = (ctx.u(), ctx.v());
    let cells: Vec<Cell> = ctx
        .slots()
        .iter()
        .zip(&openings)
        .map(|(slot, o)| {
            let x = slot.base * secret;
            let c = v * o.randomness;
            if o.choice {
                Cell { x, c: c + u }
            } else {
                Cell {
                    x: x + slot.no_point(who),
                    c,
                }
            }
        })
        .collect();
    let count = choices.iter().filter(|&&yes| yes).count() as u16;
    let rho = openings
        .iter()
        .fold(Scalar::ZERO, |acc, o| acc + o.randomness);
    Ok(OwnBallot {
        secret,
        key: RISTRETTO_BASEPOINT_POINT * secret,
        cells,
        openings,
        count,
        rho,
    })
}

#[derive(Clone, Copy)]
struct Statement {
    base: Point,
    no_point: Point,
    cell: Cell,
}

fn statements(ctx: &Context, who: Participant, cells: &[Cell]) -> Result<Vec<Statement>, String> {
    let slots = ctx.slots();
    Ok(slots
        .iter()
        .zip(cells)
        .map(|(slot, cell)| Statement {
            base: slot.base,
            no_point: slot.no_point(who),
            cell: *cell,
        })
        .collect())
}

#[derive(Zeroize)]
struct Context {
    sid: [u8; 16],
    items: Vec<String>,
}

struct Slot {
    base: Point,
    no_alice: Point,
    no_bob: Point,
}

impl Slot {
    fn no_point(&self, who: Participant) -> Point {
        match who {
            Participant::Alice => self.no_alice,
            Participant::Bob => self.no_bob,
        }
    }
}

impl Context {
    fn list_hash(&self) -> [u8; 64] {
        let mut t = transcript(b"list");
        put_u64(&mut t, b"count", self.items.len() as u64);
        for item in &self.items {
            put(&mut t, b"item", item.as_bytes());
        }
        Sha512::digest(&t).into()
    }

    fn hash_prefix(&self) -> Vec<u8> {
        let mut prefix = Vec::with_capacity(80);
        prefix.extend_from_slice(&self.sid);
        prefix.extend_from_slice(&self.list_hash());
        prefix
    }

    fn slots(&self) -> Vec<Slot> {
        let prefix = self.hash_prefix();
        (0..self.items.len() as u64)
            .map(|k| Slot {
                base: hash_to_point(&prefix, b"item", k),
                no_alice: hash_to_point(&prefix, b"no-alice", k),
                no_bob: hash_to_point(&prefix, b"no-bob", k),
            })
            .collect()
    }

    fn u(&self) -> Point {
        hash_to_point(&self.hash_prefix(), b"commit-U", 0)
    }

    fn v(&self) -> Point {
        hash_to_point(&self.hash_prefix(), b"commit-V", 0)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct BobState {
    h1: [u8; 64],
    h2: [u8; 64],
    alice: Msg1Wire,
    ballot: OwnBallot,
    msg2: Vec<u8>,
    key_ab: [u8; 32],
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct OwnBallot {
    secret: Scalar,
    key: Point,
    cells: Vec<Cell>,
    openings: Vec<Opening>,
    count: u16,
    rho: Scalar,
}

#[derive(Clone, Copy, Zeroize)]
struct Opening {
    choice: bool,
    randomness: Scalar,
}

#[derive(Clone, Copy)]
enum Participant {
    Alice,
    Bob,
}

fn decode_seed(seed: &str) -> [u8; 32] {
    *Sha256::digest(seed)
        .as_array()
        .expect("it to be a good little array")
}

#[derive(Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct Msg1Wire {
    sid: [u8; 16],
    entries: Vec<Entry>,
    key: Point,
    dh: Point,
    proof: BallotProof,
}

#[derive(Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct Entry {
    item: String,
    cell: Cell,
}

impl Msg1Wire {
    fn context(&self) -> Context {
        let items = self.entries.iter().map(|e| e.item.clone()).collect();
        Context {
            sid: self.sid,
            items,
        }
    }

    fn cells(&self) -> Vec<Cell> {
        self.entries.iter().map(|e| e.cell).collect()
    }
}

fn alice_start(items: &[String], choices: &[bool], seed: &[u8; 32]) -> Result<Vec<u8>, String> {
    Ok(alice_state(items, choices, seed)?.msg1.clone())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Msg2Wire {
    clear: ClearBallot,
    sealed: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClearBallot {
    key: Point,
    dh: Point,
    cells: Vec<Cell>,
    proof: BallotProof,
}

#[derive(Clone, Copy, Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct Cell {
    x: Point,
    c: Point,
}

#[derive(Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct ItemProof {
    yes: Branch,
    no: Branch,
}

#[derive(Clone, Copy, Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct Branch {
    challenge: Scalar,
    s1: Scalar,
    s2: Scalar,
}

#[derive(Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct BallotProof {
    challenge: Scalar,
    items: Vec<ItemProof>,
}

fn bob_respond(choices: &[bool], seed: &[u8; 32], msg1: &[u8]) -> Result<Vec<u8>, String> {
    Ok(bob_state(choices, seed, msg1)?.msg2.clone())
}

fn parse_msg1(msg1: &[u8]) -> Result<Msg1Wire, String> {
    let m: Msg1Wire = serde_json::from_slice(msg1)
        .map_err(|_| "Expected to parse msg1's wire format".to_string())?;
    if m.proof.items.len() != m.entries.len() {
        return Err(
            "The items count and entries count don't match; somehing hinky is going on.".into(),
        );
    }
    nonidentity(m.key)?;
    nonidentity(m.dh)?;

    let ctx = m.context();
    check_ballot(
        &ctx,
        Participant::Alice,
        &m.key,
        &m.cells(),
        &msg1_transcript(&ctx, &m.dh),
        &m.proof,
    )?;
    Ok(m)
}

fn read_list(msg1: &[u8]) -> Result<Vec<String>, String> {
    let m = parse_msg1(msg1)?;
    Ok(m.context().items)
}

struct Envelope<'a> {
    key: &'a [u8; 32],
    label: &'static [u8],
    h1: &'a [u8; 64],
    h2: &'a [u8; 64],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Msg3Wire {
    sealed: Vec<u8>,
}

fn alice_finish(
    items: &[String],
    choices: &[bool],
    seed: &[u8; 32],
    msg2: &[u8],
) -> Result<(Outcome, Vec<u8>), String> {
    let alice = alice_state(items, choices, seed)?;
    let ctx = &alice.ctx;
    let n = items.len();

    let wire: Msg2Wire = serde_json::from_slice(msg2)
        .map_err(|_| "Expected to parse msg2's wire format".to_string())?;
    let clear = &wire.clear;
    if clear.cells.len() != n || clear.proof.items.len() != n {
        return Err("The number of items or proofs don't match what is expected.".to_string());
    }
    nonidentity(clear.key)?;
    nonidentity(clear.dh)?;
    check_ballot(
        ctx,
        Participant::Bob,
        &clear.key,
        &clear.cells,
        &msg2_transcript(&alice.h1, &clear.dh),
        &clear.proof,
    )?;

    let h2_clear = message_digest(b"msg2-clear", clear);
    let (key_ba, key_ab) = session_keys(&alice.h1, &h2_clear, &(clear.dh * alice.dh_secret));
    let bobs = Envelope {
        key: &key_ba,
        label: b"msg2-dleq",
        h1: &alice.h1,
        h2: &h2_clear,
    };
    let theirs = check_payload(
        ctx,
        &bobs,
        &clear.key,
        &clear.cells,
        &alice.ballot.cells,
        &wire.sealed,
    )?;
    let outcome = outcome_of(&alice.ballot, &clear.cells, &theirs);

    let h2 = message_digest(b"msg2", &wire);
    let ours = Envelope {
        key: &key_ab,
        label: b"msg3-dleq",
        h1: &alice.h1,
        h2: &h2,
    };
    let sealed = make_payload(&ours, &alice.ballot, &clear.cells, &Secrets::new(seed));
    Ok((
        outcome,
        serde_json::to_vec(&Msg3Wire { sealed })
            .map_err(|_| "Expected to encode msg3".to_string())?,
    ))
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Sealed {
    count: u16,
    rho: Scalar,
    ys: Vec<Point>,
    proof: DleqProof,
}

#[derive(Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct DleqProof {
    challenge: Scalar,
    response: Scalar,
}

fn sealed_transcript(env: &Envelope, count: u16) -> Vec<u8> {
    let mut t = transcript(env.label);
    put(&mut t, b"msg1", env.h1);
    put(&mut t, b"msg2", env.h2);
    put_u64(&mut t, b"count", count as u64);
    t
}

fn make_payload(env: &Envelope, mine: &OwnBallot, theirs: &[Cell], rng: &Secrets) -> Vec<u8> {
    let pairs = scaled(theirs, &mine.secret);
    let ys = pairs.iter().map(|(_, y)| *y).collect();
    let proof = prove_dleq(
        &sealed_transcript(env, mine.count),
        rng,
        &mine.secret,
        &mine.key,
        &pairs,
    );
    let payload = Sealed {
        count: mine.count,
        rho: mine.rho,
        ys,
        proof,
    };
    seal(
        env.key,
        &concat(env.h1, env.h2),
        &serde_json::to_vec(&payload).expect("it to encode"),
    )
}

fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            &[0u8; 12].into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("ChaCha20-Poly1305 encryption does not fail for in-memory buffers")
}

fn open_sealed(key: &[u8; 32], aad: &[u8], ct: &[u8], n: usize) -> Result<Sealed, String> {
    let plain = open(key, aad, ct).ok_or("The encrypted part of this message does not decrypt: it was altered, or belongs to a different exchange.")?;
    let sealed: Sealed = serde_json::from_slice(&plain)
        .map_err(|_| "Expected to parse the sealed content".to_string())?;
    if sealed.ys.len() != n {
        return Err(
            "The sealed payload does not cover the correct number of items. I suspect foul play."
                .into(),
        );
    }
    Ok(sealed)
}

fn open(key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            &[0u8; 12].into(),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok()
}

fn concat(a: &[u8; 64], b: &[u8; 64]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(a);
    v.extend_from_slice(b);
    v
}

fn check_payload(
    ctx: &Context,
    env: &Envelope,
    their_key: &Point,
    their_cells: &[Cell],
    mine: &[Cell],
    sealed: &[u8],
) -> Result<Sealed, String> {
    let payload = open_sealed(env.key, &concat(env.h1, env.h2), sealed, mine.len())?;
    check_count(ctx, their_cells, payload.count, &payload.rho)?;
    if !verify_dleq(
        &sealed_transcript(env, payload.count),
        their_key,
        &with_claims(mine, &payload.ys),
        &payload.proof,
    ) {
        return Err("A proof in this message does not check out: the other person's page did not follow the protocol, or the message was altered.".into());
    }
    Ok(payload)
}

fn bob_finish(
    choices: &[bool],
    seed: &[u8; 32],
    msg1: &[u8],
    msg3: &[u8],
) -> Result<Outcome, String> {
    let bob = bob_state(choices, seed, msg1)?;
    let ctx = bob.alice.context();
    let theirs_cells = bob.alice.cells();

    let wire: Msg3Wire = serde_json::from_slice(msg3)
        .map_err(|_| "Couldn't decode msg3's wire format".to_string())?;
    let alices = Envelope {
        key: &bob.key_ab,
        label: b"msg3-dleq",
        h1: &bob.h1,
        h2: &bob.h2,
    };
    let theirs = check_payload(
        &ctx,
        &alices,
        &bob.alice.key,
        &theirs_cells,
        &bob.ballot.cells,
        &wire.sealed,
    )?;
    Ok(outcome_of(&bob.ballot, &theirs_cells, &theirs))
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Secrets {
    seed: [u8; 32],
}

impl Secrets {
    fn new(seed: &[u8; 32]) -> Secrets {
        Secrets { seed: *seed }
    }

    fn bind(&self, t: &[u8]) -> Secrets {
        let mut b = transcript(b"bind");
        put(&mut b, b"seed", &self.seed);
        put(&mut b, b"transcript", &Sha512::digest(t));
        let d: [u8; 64] = Sha512::digest(&b).into();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&d[..32]);
        Secrets { seed }
    }

    fn bytes(&self, label: &[u8], index: u64) -> [u8; 64] {
        let mut t = transcript(b"secret");
        put(&mut t, b"seed", &self.seed);
        put(&mut t, b"label", label);
        put_u64(&mut t, b"index", index);
        Sha512::digest(&t).into()
    }

    fn scalar(&self, label: &[u8], index: u64) -> Scalar {
        Scalar::from_bytes_mod_order_wide(&self.bytes(label, index))
    }

    fn nonzero_scalar(&self, label: &[u8]) -> Result<Scalar, String> {
        let s = self.scalar(label, 0);
        if s != Scalar::ZERO {
            Ok(s)
        } else {
            Err("You got _incredibly_ unlucky. Try again.".to_string())
        }
    }
}

fn check_ballot(
    ctx: &Context,
    who: Participant,
    key: &Point,
    cells: &[Cell],
    tr: &[u8],
    proof: &BallotProof,
) -> Result<(), String> {
    let view = ballot_view(ctx, *key, statements(ctx, who, cells)?);
    if verify_ballot(tr, &view, proof) {
        Ok(())
    } else {
        Err("A proof in this message does not check out: the other person's page did not follow the protocol, or the message was altered.".into())
    }
}

fn verify_ballot(tr: &[u8], b: &BallotStatement, p: &BallotProof) -> bool {
    if b.items.len() != p.items.len() {
        return false;
    }
    if p.items
        .iter()
        .any(|item| item.yes.challenge + item.no.challenge != p.challenge)
    {
        return false;
    }
    let commitments: Vec<[Point; 3]> = b
        .items
        .iter()
        .zip(&p.items)
        .flat_map(|(s, item)| {
            let br = branches(s, &b.u);
            [
                simulate(b, s, &br[0], &item.yes),
                simulate(b, s, &br[1], &item.no),
            ]
        })
        .collect();
    ballot_challenge(tr, b, &commitments) == p.challenge
}

fn combine(tr: &[u8], key: &Point, pairs: &[(Point, Point)]) -> (Vec<u8>, Point, Point) {
    let mut t = tr.to_vec();
    let bases: Vec<Point> = pairs.iter().map(|(base, _)| *base).collect();
    let outs: Vec<Point> = pairs.iter().map(|(_, out)| *out).collect();
    put_point(&mut t, b"key", key);
    put_points(&mut t, b"bases", &bases);
    put_points(&mut t, b"outs", &outs);
    let (m, z) = pairs.iter().enumerate().fold(
        (Point::identity(), Point::identity()),
        |(m, z), (k, (base, out))| {
            let c = challenge_at(&t, b"dleq-weight", k as u64);
            (m + base * c, z + out * c)
        },
    );
    (t, m, z)
}

fn dleq_challenge(t: &[u8], m: &Point, z: &Point, t1: &Point, t2: &Point) -> Scalar {
    let mut t = t.to_vec();
    put_point(&mut t, b"m", m);
    put_point(&mut t, b"z", z);
    put_point(&mut t, b"t1", t1);
    put_point(&mut t, b"t2", t2);
    challenge(&t, b"dleq")
}

fn scaled(cells: &[Cell], s: &Scalar) -> Vec<(Point, Point)> {
    cells.iter().map(|c| (c.x, c.x * s)).collect()
}

fn outcome_of(mine: &OwnBallot, theirs_cells: &[Cell], theirs: &Sealed) -> Outcome {
    Outcome {
        matches: matches(&scaled(theirs_cells, &mine.secret), &theirs.ys),
        mine: mine.count as u32,
        theirs: theirs.count as u32,
    }
}

fn prove_dleq(
    tr: &[u8],
    secrets: &Secrets,
    secret: &Scalar,
    key: &Point,
    pairs: &[(Point, Point)],
) -> DleqProof {
    let (t, m, z) = combine(tr, key, pairs);
    let w = secrets.bind(&t).scalar(b"dleq-w", 0);
    let e = dleq_challenge(&t, &m, &z, &(RISTRETTO_BASEPOINT_POINT * w), &(m * w));
    DleqProof {
        challenge: e,
        response: w + e * secret,
    }
}

fn verify_dleq(tr: &[u8], key: &Point, pairs: &[(Point, Point)], p: &DleqProof) -> bool {
    let (t, m, z) = combine(tr, key, pairs);
    let t1 = RISTRETTO_BASEPOINT_POINT * p.response - key * p.challenge;
    let t2 = m * p.response - z * p.challenge;
    dleq_challenge(&t, &m, &z, &t1, &t2) == p.challenge
}

fn check_count(ctx: &Context, cells: &[Cell], count: u16, rho: &Scalar) -> Result<(), String> {
    if count as usize > cells.len() {
        return Err("The other person's stated number of yes answers does not match what they committed to.".into());
    }
    let mut sum = Point::identity();
    for cell in cells {
        sum += cell.c;
    }
    let expected = ctx.u() * Scalar::from(count as u64) + ctx.v() * rho;
    if sum == expected {
        Ok(())
    } else {
        Err("The other person's stated number of yes answers does not match what they committed to.".into())
    }
}

fn with_claims(cells: &[Cell], claims: &[Point]) -> Vec<(Point, Point)> {
    cells.iter().zip(claims).map(|(c, y)| (c.x, *y)).collect()
}

fn matches(mine: &[(Point, Point)], theirs: &[Point]) -> Vec<bool> {
    mine.iter().zip(theirs).map(|((_, m), t)| m == t).collect()
}
