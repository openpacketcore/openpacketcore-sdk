use super::*;

fn attempt(number: u64) -> PageAttempt {
    PageAttempt {
        number,
        binding: [number as u8; 32],
    }
}

fn build<R>(window: &mut ReplyWindow<R>, number: u64) -> BuildToken {
    match window.begin(attempt(number)).unwrap() {
        ReplyAdmission::Build(token) => token,
        _ => panic!("expected one page builder"),
    }
}

#[test]
fn lost_partial_and_no_progress_replies_replay_identical_owned_response() {
    let mut window = ReplyWindow::new();
    for (number, text) in [
        "partial after key 10",
        "no progress; limit 128",
        "partial after key 11",
    ]
    .into_iter()
    .enumerate()
    {
        let token = build(&mut window, number as u64);
        let reply = Arc::new(text.to_owned());
        window.publish(&token, Arc::clone(&reply), true).unwrap();
        for _ in 0..3 {
            let ReplyAdmission::Replay(replayed) = window.begin(attempt(number as u64)).unwrap()
            else {
                panic!("lost reply was rebuilt")
            };
            assert!(Arc::ptr_eq(&reply, &replayed));
        }
    }
}

#[test]
fn duplicate_while_building_waits_for_the_same_attempt() {
    let mut window = ReplyWindow::<()>::new();
    let token = build(&mut window, 0);
    assert!(matches!(
        window.begin(attempt(0)),
        Ok(ReplyAdmission::Pending)
    ));
    window.publish(&token, Arc::new(()), true).unwrap();
    assert!(matches!(
        window.begin(attempt(0)),
        Ok(ReplyAdmission::Replay(_))
    ));
}

#[test]
fn changed_binding_cannot_reuse_an_inflight_or_cached_attempt_number() {
    let mut window = ReplyWindow::<()>::new();
    let token = build(&mut window, 0);
    let forged = PageAttempt {
        number: 0,
        binding: [99; 32],
    };
    assert!(matches!(
        window.begin(forged),
        Err(ReplyWindowError::InvalidRequest)
    ));
    window.publish(&token, Arc::new(()), true).unwrap();
    assert!(matches!(
        window.begin(forged),
        Err(ReplyWindowError::InvalidRequest)
    ));
    assert!(matches!(
        window.begin(attempt(0)),
        Ok(ReplyAdmission::Replay(_))
    ));
}

#[test]
fn successor_acknowledgement_releases_the_only_retained_reply() {
    let mut window = ReplyWindow::new();
    let first = build(&mut window, 0);
    let reply = Arc::new(vec![5; 1024]);
    let weak = Arc::downgrade(&reply);
    window.publish(&first, reply, true).unwrap();
    assert!(weak.upgrade().is_some());
    let next = build(&mut window, 1);
    assert!(weak.upgrade().is_none());
    assert!(matches!(
        window.begin(attempt(0)),
        Err(ReplyWindowError::InvalidRequest)
    ));
    window.publish(&next, Arc::new(vec![6; 128]), true).unwrap();
    assert!(matches!(
        window.begin(attempt(2)),
        Ok(ReplyAdmission::Build(_))
    ));
}

#[test]
fn unsolicited_future_attempt_does_not_acknowledge_a_cached_reply() {
    let mut window = ReplyWindow::<()>::new();
    assert!(matches!(
        window.begin(attempt(5)),
        Err(ReplyWindowError::InvalidRequest)
    ));
    let token = build(&mut window, 0);
    window.publish(&token, Arc::new(()), true).unwrap();
    assert!(matches!(
        window.begin(attempt(2)),
        Err(ReplyWindowError::InvalidRequest)
    ));
    assert!(matches!(
        window.begin(attempt(0)),
        Ok(ReplyAdmission::Replay(_))
    ));
}

#[test]
fn terminal_reply_is_replayable_until_invalidated() {
    let mut window = ReplyWindow::<()>::new();
    let token = build(&mut window, 0);
    window.publish(&token, Arc::new(()), false).unwrap();
    assert!(matches!(
        window.begin(attempt(0)),
        Ok(ReplyAdmission::Replay(_))
    ));
    assert!(matches!(
        window.begin(attempt(1)),
        Err(ReplyWindowError::InvalidRequest)
    ));
    window.invalidate();
    assert!(matches!(
        window.begin(attempt(0)),
        Err(ReplyWindowError::Closed)
    ));
}

#[test]
fn cancellation_allows_retry_but_late_old_builder_cannot_publish_or_cancel_it() {
    let mut window = ReplyWindow::<()>::new();
    let old = build(&mut window, 0);
    assert!(window.cancel(&old));
    assert!(!window.cancel(&old));
    let current = build(&mut window, 0);
    assert_eq!(
        window.publish(&old, Arc::new(()), true),
        Err(ReplyWindowError::InvalidRequest)
    );
    assert!(!window.cancel(&old));
    assert!(matches!(
        window.begin(attempt(0)),
        Ok(ReplyAdmission::Pending)
    ));
    window.publish(&current, Arc::new(()), true).unwrap();
}

#[test]
fn invalidation_drops_cached_response_and_refuses_a_late_publish() {
    let mut window = ReplyWindow::new();
    let token = build(&mut window, 0);
    let reply = Arc::new(vec![1; 1024]);
    let weak = Arc::downgrade(&reply);
    window.publish(&token, reply, true).unwrap();
    window.invalidate();
    assert!(weak.upgrade().is_none());
    assert_eq!(
        window.publish(&token, Arc::new(vec![]), true),
        Err(ReplyWindowError::Closed)
    );
    assert!(!window.cancel(&token));
    assert!(matches!(
        window.begin(attempt(1)),
        Err(ReplyWindowError::Closed)
    ));
}

#[test]
fn one_builder_can_publish_only_once() {
    let mut window = ReplyWindow::new();
    let token = build(&mut window, 0);
    window.publish(&token, Arc::new(1), true).unwrap();
    assert_eq!(
        window.publish(&token, Arc::new(2), true),
        Err(ReplyWindowError::InvalidRequest)
    );
    let ReplyAdmission::Replay(reply) = window.begin(attempt(0)).unwrap() else {
        panic!("cached result missing")
    };
    assert_eq!(*reply, 1);
}

#[test]
fn attempt_and_builder_counter_exhaustion_are_terminal() {
    let mut window = ReplyWindow::<()>::new();
    window.expected = Some(u64::MAX);
    let token = build(&mut window, u64::MAX);
    assert_eq!(
        window.publish(&token, Arc::new(()), true),
        Err(ReplyWindowError::CounterExhausted)
    );
    assert!(matches!(
        window.begin(attempt(u64::MAX)),
        Err(ReplyWindowError::Closed)
    ));
    let mut window = ReplyWindow::<()>::new();
    window.generation = u64::MAX;
    assert!(matches!(
        window.begin(attempt(0)),
        Err(ReplyWindowError::CounterExhausted)
    ));
    assert!(matches!(
        window.begin(attempt(0)),
        Err(ReplyWindowError::Closed)
    ));
}
