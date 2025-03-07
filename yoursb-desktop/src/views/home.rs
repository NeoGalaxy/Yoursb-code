use iced::{
    widget::{button, center, column, row, text, text_input},
    Alignment, Element,
};

use crate::Message;

pub fn view() -> Element<'static, Message> {
    center(
        column![
            text("YourSB Code").size(50),
            column![
                button("Open global instance"),
                column![
                    text("Open local instance"),
                    row![text_input("Instance path...", ""), button("Browse..."),]
                ]
                .align_x(Alignment::Center),
            ]
            .align_x(Alignment::Center)
        ]
        .align_x(Alignment::Center),
    )
    .into()
}
