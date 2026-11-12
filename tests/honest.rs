use insta::assert_snapshot;
use kiss::*;

#[test]
fn honest_protocol() {
    let alice_answers = vec![true, false, true];
    let bob_answers = vec![true, true, false];

    let alice_seed = "4".to_string();
    let bob_seed = "19".to_string();

    let items = vec![
        "Bears".to_string(),
        "Beets".to_string(),
        "Battlestar Galactica".to_string(),
    ];

    let Ok(Reply::Msg1 { msg1 }) = handle(Request::AliceStart {
        seed: alice_seed.clone(),
        choices: alice_answers.clone(),
        items: items.clone(),
    }) else {
        panic!("No.")
    };

    assert_snapshot!(msg1);

    let Ok(Reply::Items { items: items2 }) = handle(Request::ReadList { msg1: msg1.clone() })
    else {
        panic!("Don't.")
    };

    assert_eq!(items, items2);

    let Ok(Reply::Msg2 { msg2 }) = handle(Request::BobRespond {
        seed: bob_seed.clone(),
        choices: bob_answers.clone(),
        msg1: msg1.clone(),
    }) else {
        panic!("Stop it!")
    };

    assert_snapshot!(msg2);

    let Ok(Reply::AliceDone {
        outcome: outcome_alice,
        msg3,
    }) = handle(Request::AliceFinish {
        seed: alice_seed,
        choices: alice_answers,
        items,
        msg2,
    })
    else {
        panic!("Forgive me.")
    };

    assert_snapshot!(msg3);

    let Ok(Reply::BobDone {
        outcome: outcome_bob,
    }) = handle(Request::BobFinish {
        seed: bob_seed,
        choices: bob_answers,
        msg1,
        msg3,
    })
    else {
        panic!("Kills you dead.")
    };

    assert_eq!(outcome_alice, outcome_bob);
    assert_eq!(
        outcome_alice,
        Outcome {
            mine: 2,
            theirs: 2,
            matches: vec![true, false, false],
        }
    );
}

#[test]
fn one_match() {
    let alice_answers = vec![true];
    let bob_answers = vec![true];

    let alice_seed = "4".to_string();
    let bob_seed = "19".to_string();

    let items = vec!["Bears".to_string()];

    let Ok(Reply::Msg1 { msg1 }) = handle(Request::AliceStart {
        seed: alice_seed.clone(),
        choices: alice_answers.clone(),
        items: items.clone(),
    }) else {
        panic!("No.")
    };

    assert_snapshot!(msg1);

    let Ok(Reply::Items { items: items2 }) = handle(Request::ReadList { msg1: msg1.clone() })
    else {
        panic!("Don't.")
    };

    assert_eq!(items, items2);

    let Ok(Reply::Msg2 { msg2 }) = handle(Request::BobRespond {
        seed: bob_seed.clone(),
        choices: bob_answers.clone(),
        msg1: msg1.clone(),
    }) else {
        panic!("Stop it!")
    };

    assert_snapshot!(msg2);

    let Ok(Reply::AliceDone {
        outcome: outcome_alice,
        msg3,
    }) = handle(Request::AliceFinish {
        seed: alice_seed,
        choices: alice_answers,
        items,
        msg2,
    })
    else {
        panic!("Forgive me.")
    };

    assert_snapshot!(msg3);

    let Ok(Reply::BobDone {
        outcome: outcome_bob,
    }) = handle(Request::BobFinish {
        seed: bob_seed,
        choices: bob_answers,
        msg1,
        msg3,
    })
    else {
        panic!("Kills you dead.")
    };

    assert_eq!(outcome_alice, outcome_bob);
    assert_eq!(
        outcome_alice,
        Outcome {
            mine: 1,
            theirs: 1,
            matches: vec![true],
        }
    );
}

#[test]
fn no_match() {
    let alice_answers = vec![false];
    let bob_answers = vec![true];

    let alice_seed = "4".to_string();
    let bob_seed = "19".to_string();

    let items = vec!["Bears".to_string()];

    let Ok(Reply::Msg1 { msg1 }) = handle(Request::AliceStart {
        seed: alice_seed.clone(),
        choices: alice_answers.clone(),
        items: items.clone(),
    }) else {
        panic!("No.")
    };

    assert_snapshot!(msg1);

    let Ok(Reply::Items { items: items2 }) = handle(Request::ReadList { msg1: msg1.clone() })
    else {
        panic!("Don't.")
    };

    assert_eq!(items, items2);

    let Ok(Reply::Msg2 { msg2 }) = handle(Request::BobRespond {
        seed: bob_seed.clone(),
        choices: bob_answers.clone(),
        msg1: msg1.clone(),
    }) else {
        panic!("Stop it!")
    };

    assert_snapshot!(msg2);

    let Ok(Reply::AliceDone {
        outcome: outcome_alice,
        msg3,
    }) = handle(Request::AliceFinish {
        seed: alice_seed,
        choices: alice_answers,
        items,
        msg2,
    })
    else {
        panic!("Forgive me.")
    };

    assert_snapshot!(msg3);

    let Ok(Reply::BobDone {
        outcome: outcome_bob,
    }) = handle(Request::BobFinish {
        seed: bob_seed,
        choices: bob_answers,
        msg1,
        msg3,
    })
    else {
        panic!("Kills you dead.")
    };

    assert_eq!(
        outcome_bob,
        Outcome {
            mine: 1,
            theirs: 0,
            matches: vec![false],
        }
    );
    assert_eq!(
        outcome_alice,
        Outcome {
            mine: 0,
            theirs: 1,
            matches: vec![false],
        }
    );
}
