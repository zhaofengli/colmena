use indicatif::ProgressStyle;

pub fn get_spinner_styles(node_name_alignment: usize) -> (ProgressStyle, ProgressStyle) {
    let template = format!("{{prefix:>{}.bold.dim}} {{spinner}} {{elapsed}} {{wide_msg}}", node_name_alignment);

    (
        ProgressStyle::default_spinner()
        .tick_chars("🕛🕐🕑🕒🕓🕔🕕🕖🕗🕘🕙🕚✅")
        .template(&template),

        ProgressStyle::default_spinner()
        .tick_chars("❌❌")
        .template(&template),
    )
}
