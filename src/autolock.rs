//! Inactivity-based auto-lock.

use std::time::{Duration, Instant};

/// Auto-lock timeout: three minutes of inactivity.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3 * 60);

/// Monotonic inactivity timer.
pub struct AutoLock {
    timeout: Duration,
    last_activity: Instant,
}

impl AutoLock {
    pub fn new() -> Self {
        Self::with_timeout(DEFAULT_TIMEOUT)
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            timeout,
            last_activity: Instant::now(),
        }
    }

    pub fn note_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn note_activity_at(&mut self, now: Instant) {
        self.last_activity = now;
    }

    pub fn should_lock(&self) -> bool {
        self.should_lock_at(Instant::now())
    }

    pub fn should_lock_at(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_activity) >= self.timeout
    }

    pub fn remaining(&self) -> Duration {
        self.remaining_at(Instant::now())
    }

    pub fn remaining_at(&self, now: Instant) -> Duration {
        let elapsed = now.saturating_duration_since(self.last_activity);
        self.timeout.saturating_sub(elapsed)
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl Default for AutoLock {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether a single egui event represents genuine user input for the purpose
/// of resetting the inactivity timer.
pub fn is_user_activity_event(event: &egui::Event) -> bool {
    use egui::Event;
    matches!(
        event,
        Event::Key { pressed: true, .. }
            | Event::Text(_)
            | Event::Paste(_)
            | Event::Copy
            | Event::Cut
            | Event::PointerMoved(_)
            | Event::PointerButton { pressed: true, .. }
            | Event::MouseWheel { .. }
    )
}

/// Whether the current frame's input state contains any user activity.
pub fn user_activity_in(input: &egui::InputState) -> bool {
    input.events.iter().any(is_user_activity_event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui::{Event, Key, Modifiers, MouseWheelUnit, Pos2, Vec2};

    #[test]
    fn fresh_timer_does_not_lock_immediately() {
        let al = AutoLock::with_timeout(Duration::from_secs(180));
        assert!(!al.should_lock());
    }

    #[test]
    fn locks_exactly_at_the_timeout_boundary() {
        let start = Instant::now();
        let mut al = AutoLock::with_timeout(Duration::from_secs(180));
        al.note_activity_at(start);
        assert!(!al.should_lock_at(start + Duration::from_secs(179)));
        assert!(al.should_lock_at(start + Duration::from_secs(180)));
        assert!(al.should_lock_at(start + Duration::from_secs(181)));
    }

    #[test]
    fn activity_resets_the_timer() {
        let start = Instant::now();
        let mut al = AutoLock::with_timeout(Duration::from_secs(180));
        al.note_activity_at(start);
        let almost = start + Duration::from_secs(179);
        assert!(!al.should_lock_at(almost));
        al.note_activity_at(almost);
        assert!(!al.should_lock_at(almost + Duration::from_secs(179)));
        assert!(al.should_lock_at(almost + Duration::from_secs(180)));
    }

    #[test]
    fn remaining_saturates_at_zero() {
        let start = Instant::now();
        let mut al = AutoLock::with_timeout(Duration::from_secs(180));
        al.note_activity_at(start);
        assert_eq!(al.remaining_at(start), Duration::from_secs(180));
        assert_eq!(
            al.remaining_at(start + Duration::from_secs(60)),
            Duration::from_secs(120)
        );
        assert_eq!(
            al.remaining_at(start + Duration::from_secs(500)),
            Duration::ZERO
        );
    }

    #[test]
    fn timeout_is_reported_verbatim() {
        let al = AutoLock::with_timeout(Duration::from_secs(42));
        assert_eq!(al.timeout(), Duration::from_secs(42));
    }

    fn key_press() -> Event {
        Event::Key {
            key: Key::A,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: Modifiers::default(),
        }
    }

    fn key_release() -> Event {
        Event::Key {
            key: Key::A,
            physical_key: None,
            pressed: false,
            repeat: false,
            modifiers: Modifiers::default(),
        }
    }

    #[test]
    fn key_press_counts_as_activity() {
        assert!(is_user_activity_event(&key_press()));
    }

    #[test]
    fn key_auto_repeat_counts_as_activity() {
        let ev = Event::Key {
            key: Key::ArrowDown,
            physical_key: None,
            pressed: true,
            repeat: true,
            modifiers: Modifiers::default(),
        };
        assert!(is_user_activity_event(&ev));
    }

    #[test]
    fn key_release_does_not_count() {
        assert!(!is_user_activity_event(&key_release()));
    }

    #[test]
    fn text_paste_copy_cut_count_as_activity() {
        assert!(is_user_activity_event(&Event::Text("a".into())));
        assert!(is_user_activity_event(&Event::Paste("x".into())));
        assert!(is_user_activity_event(&Event::Copy));
        assert!(is_user_activity_event(&Event::Cut));
    }

    #[test]
    fn pointer_movement_counts_as_activity() {
        assert!(is_user_activity_event(&Event::PointerMoved(Pos2::new(
            1.0, 2.0
        ))));
    }

    #[test]
    fn pointer_button_press_counts_but_release_does_not() {
        let press = Event::PointerButton {
            pos: egui::pos2(10.0, 20.0),
            button: egui::PointerButton::Primary,
            pressed: true,
            modifiers: Modifiers::default(),
        };
        let release = Event::PointerButton {
            pos: egui::pos2(10.0, 20.0),
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: Modifiers::default(),
        };
        assert!(is_user_activity_event(&press));
        assert!(!is_user_activity_event(&release));
    }

    #[test]
    fn scroll_counts_as_activity() {
        let ev = Event::MouseWheel {
            unit: MouseWheelUnit::Point,
            delta: Vec2::new(0.0, -20.0),
            modifiers: Modifiers::default(),
        };
        assert!(is_user_activity_event(&ev));
    }

    #[test]
    fn framework_events_do_not_count() {
        assert!(!is_user_activity_event(&Event::WindowFocused(true)));
        assert!(!is_user_activity_event(&Event::PointerGone));
    }

    #[test]
    fn input_state_with_no_events_has_no_activity() {
        let input = egui::InputState::default();
        assert!(!user_activity_in(&input));
    }

    #[test]
    fn input_state_with_a_key_press_has_activity() {
        let mut input = egui::InputState::default();
        input.events.push(key_press());
        assert!(user_activity_in(&input));
    }

    #[test]
    fn input_state_with_only_framework_events_has_no_activity() {
        let mut input = egui::InputState::default();
        input.events.push(Event::WindowFocused(false));
        input.events.push(Event::PointerGone);
        assert!(!user_activity_in(&input));
    }
}
