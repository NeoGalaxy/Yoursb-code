pub mod views;

use iced::Element;

#[derive(Default)]
struct Counter {
    value: u64,
}

#[derive(Debug, Clone)]
pub enum Message {
    Increment,
}

fn update(counter: &mut Counter, message: Message) {
    match message {
        Message::Increment => counter.value += 1,
    }
}

fn view(_counter: &Counter) -> Element<Message> {
    // button(text(counter.value))
    //     .on_press(Message::Increment)
    //     .into()
    views::home::view()
}

fn main() -> iced::Result {
    iced::run("YourSB Code Desktop", update, view)
}
