//! The pet window through Slint's testing backend, found by accessible labels.

use std::cell::RefCell;
use std::rc::Rc;

use i_slint_backend_testing::ElementHandle;
use qalaa_guardian_pet::mood::Mood;
use qalaa_guardian_pet::{actions, mood_text, text, Lang, PetWindow};
use slint::{ComponentHandle, ModelRc, VecModel};

#[test]
fn pet_window() {
    i_slint_backend_testing::init_no_event_loop();
    let pet = PetWindow::new().expect("window");
    pet.window().set_size(slint::LogicalSize::new(400.0, 520.0));
    pet.set_sprite_label(text("sprite", Lang::En).into());
    pet.set_sprite_y(400.0);
    pet.set_actions(ModelRc::from(Rc::new(VecModel::from(actions(Lang::En, false)))));

    // The sprite is a button a screen reader can press.
    let clicks = Rc::new(RefCell::new(0));
    {
        let clicks = Rc::clone(&clicks);
        pet.on_sprite_clicked(move || *clicks.borrow_mut() += 1);
    }
    let sprite: Vec<_> = ElementHandle::find_by_accessible_label(&pet, "Qalaa Guardian: open quick actions").collect();
    assert_eq!(sprite.len(), 1);
    sprite[0].invoke_accessible_default_action();
    assert_eq!(*clicks.borrow(), 1);

    // Closed popover: no actions on screen.
    assert_eq!(ElementHandle::find_by_accessible_label(&pet, "Run a quick scan").count(), 0);

    // Open, offline: service actions are disabled, local ones work.
    pet.set_popover_open(true);
    pet.set_mood(Mood::Alert.as_str().into());
    pet.set_mood_text(mood_text(Mood::Alert, Lang::En).into());
    let ran = Rc::new(RefCell::new(Vec::<String>::new()));
    {
        let ran = Rc::clone(&ran);
        pet.on_action(move |id| ran.borrow_mut().push(id.to_string()));
    }
    let scan: Vec<_> = ElementHandle::find_by_accessible_label(&pet, "Run a quick scan").collect();
    assert_eq!(scan.len(), 1);
    assert_eq!(scan[0].accessible_enabled(), Some(false));
    let snooze: Vec<_> = ElementHandle::find_by_accessible_label(&pet, "Hide for 2 hours").collect();
    snooze[0].invoke_accessible_default_action();
    assert_eq!(*ran.borrow(), vec!["snooze".to_owned()]);
    // The card is a group named by the mood, with the mood as its heading.
    assert!(ElementHandle::find_by_accessible_label(&pet, "Needs your attention")
        .any(|e| e.accessible_role() == Some(i_slint_core::items::AccessibleRole::Groupbox)));

    // Online: the scan works.
    pet.set_actions(ModelRc::from(Rc::new(VecModel::from(actions(Lang::En, true)))));
    let scan: Vec<_> = ElementHandle::find_by_accessible_label(&pet, "Run a quick scan").collect();
    assert_eq!(scan[0].accessible_enabled(), Some(true));
    scan[0].invoke_accessible_default_action();
    assert_eq!(ran.borrow().last().map(String::as_str), Some("scan.quick"));

    // Every skin builds and draws.
    for skin in qalaa_guardian_pet::SKINS {
        pet.set_skin(skin.into());
        assert_eq!(
            ElementHandle::find_by_accessible_label(&pet, "Qalaa Guardian: open quick actions").count(),
            1
        );
    }
}
