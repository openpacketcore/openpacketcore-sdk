//! One ordering boundary across every graph in a local scope.

use super::ScopeError;

pub(super) trait RetirementPort {
    fn preflight(&mut self) -> Result<(), ScopeError>;
    fn detach(&mut self) -> Result<(), ScopeError>;
    fn unpin_programs(&mut self) -> Result<(), ScopeError>;
    fn close_programs(&mut self);
    fn references(&mut self) -> Result<(), ScopeError>;
    fn unpin_maps(&mut self) -> Result<(), ScopeError>;
    fn close_maps(&mut self);
}

#[cfg(test)]
fn run(ports: &mut [impl RetirementPort]) -> Result<(), ScopeError> {
    run_checked(ports, &|| Ok(()))
}

pub(super) fn run_checked(
    ports: &mut [impl RetirementPort],
    check: &(impl Fn() -> Result<(), ScopeError> + ?Sized),
) -> Result<(), ScopeError> {
    for port in ports.iter_mut() {
        check()?;
        port.preflight()?;
    }
    for port in ports.iter_mut() {
        check()?;
        port.detach()?;
    }
    for port in ports.iter_mut() {
        check()?;
        port.unpin_programs()?;
    }
    for port in ports.iter_mut() {
        check()?;
        port.close_programs();
    }
    for port in ports.iter_mut() {
        check()?;
        port.references()?;
    }
    for port in ports.iter_mut() {
        check()?;
        port.unpin_maps()?;
    }
    for port in ports.iter_mut() {
        check()?;
        port.references()?;
    }
    for port in ports.iter_mut() {
        check()?;
        port.close_maps();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct State {
        detached: [bool; 2],
        programs_unpinned: [bool; 2],
        programs_closed: [bool; 2],
        maps_unpinned: [bool; 2],
        effects: usize,
    }
    struct Graph {
        index: usize,
        state: Arc<Mutex<State>>,
        conflict: bool,
    }
    impl RetirementPort for Graph {
        fn preflight(&mut self) -> Result<(), ScopeError> {
            if self.conflict {
                Err(ScopeError::Conflict)
            } else {
                Ok(())
            }
        }
        fn detach(&mut self) -> Result<(), ScopeError> {
            let mut state = self.state.lock().unwrap();
            state.detached[self.index] = true;
            state.effects += 1;
            Ok(())
        }
        fn unpin_programs(&mut self) -> Result<(), ScopeError> {
            let mut state = self.state.lock().unwrap();
            assert_eq!(
                state.detached, [true; 2],
                "one backend still has a live data hook"
            );
            state.programs_unpinned[self.index] = true;
            state.effects += 1;
            Ok(())
        }
        fn close_programs(&mut self) {
            let mut state = self.state.lock().unwrap();
            assert_eq!(state.programs_unpinned, [true; 2]);
            state.programs_closed[self.index] = true;
        }
        fn references(&mut self) -> Result<(), ScopeError> {
            assert_eq!(self.state.lock().unwrap().programs_closed, [true; 2]);
            Ok(())
        }
        fn unpin_maps(&mut self) -> Result<(), ScopeError> {
            let mut state = self.state.lock().unwrap();
            assert_eq!(state.programs_closed, [true; 2]);
            state.maps_unpinned[self.index] = true;
            state.effects += 1;
            Ok(())
        }
        fn close_maps(&mut self) {
            assert_eq!(self.state.lock().unwrap().maps_unpinned, [true; 2]);
        }
    }
    fn graphs() -> ([Graph; 2], Arc<Mutex<State>>) {
        let state = Arc::new(Mutex::new(State::default()));
        (
            [
                Graph {
                    index: 0,
                    state: state.clone(),
                    conflict: false,
                },
                Graph {
                    index: 1,
                    state: state.clone(),
                    conflict: false,
                },
            ],
            state,
        )
    }
    #[test]
    fn every_graph_detaches_before_any_program_or_map_pin_retires() {
        let (mut graphs, state) = graphs();
        run(&mut graphs).unwrap();
        assert_eq!(state.lock().unwrap().effects, 6);
    }
    #[test]
    fn a_conflict_in_the_last_graph_is_found_before_the_first_effect() {
        let (mut graphs, state) = graphs();
        graphs[1].conflict = true;
        assert_eq!(run(&mut graphs), Err(ScopeError::Conflict));
        assert_eq!(state.lock().unwrap().effects, 0);
    }
    #[test]
    fn an_exhausted_attempt_stops_before_another_graph_effect() {
        let (mut graphs, state) = graphs();
        let check = || {
            if state.lock().unwrap().effects == 0 {
                Ok(())
            } else {
                Err(ScopeError::Inspection)
            }
        };
        assert_eq!(
            run_checked(&mut graphs, &check),
            Err(ScopeError::Inspection)
        );
        let state = state.lock().unwrap();
        assert_eq!(state.detached, [true, false]);
        assert_eq!(state.programs_unpinned, [false; 2]);
        assert_eq!(state.maps_unpinned, [false; 2]);
    }
}
