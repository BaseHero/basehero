//! Render a note's Yjs XML body as portable Markdown.

use bh_proto::ObjectId;
use yrs::types::text::YChange;
use yrs::{Any, Out, ReadTxn, Text, Xml, XmlElementRef, XmlFragment, XmlFragmentRef, XmlOut};

const INLINE: &str = "\\*_~`[]()<>";

/// Escapes the inline punctuation that would otherwise become emphasis, code,
/// links or raw HTML. A period or hash mid-sentence needs no escape.
fn escape_inline(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if INLINE.contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Escapes a block marker only where Markdown would read one: at the start of a
/// line, in this text or after a hard break.
fn escape_line_start(s: &str) -> String {
    let mut chars = s.char_indices();
    match chars.next() {
        Some((_, c)) if "#>-+=".contains(c) => format!("\\{s}"),
        Some((_, c)) if c.is_ascii_digit() => {
            let digits = s
                .char_indices()
                .take_while(|(_, c)| c.is_ascii_digit())
                .count();
            match s[digits..].chars().next() {
                Some('.' | ')') => {
                    let (before, after) = s.split_at(digits);
                    format!("{before}\\{after}")
                }
                _ => s.to_owned(),
            }
        }
        _ => s.to_owned(),
    }
}

fn attr<T: ReadTxn>(el: &XmlElementRef, txn: &T, key: &str) -> Option<String> {
    match el.get_attribute(txn, key)? {
        Out::Any(Any::String(s)) => Some(s.to_string()),
        Out::Any(Any::Number(n)) => Some(n.to_string()),
        Out::Any(Any::Bool(b)) => Some(b.to_string()),
        _ => None,
    }
}

fn inline<T: ReadTxn>(
    el: &XmlElementRef,
    txn: &T,
    links: &dyn Fn(ObjectId) -> Option<String>,
) -> String {
    let mut out = String::new();
    let mut line_start = true;
    for child in el.children(txn) {
        match child {
            XmlOut::Text(text) => {
                for chunk in text.diff(txn, |_: YChange| ()) {
                    if let Out::Any(Any::String(s)) = chunk.insert {
                        let escaped = escape_inline(&s);
                        let mut v = if line_start {
                            escape_line_start(&escaped)
                        } else {
                            escaped
                        };
                        line_start = s.ends_with('\n');
                        if let Some(a) = chunk.attributes {
                            let on = |key: &str| {
                                a.get(key)
                                    .is_some_and(|v| !matches!(v, Any::Null | Any::Bool(false)))
                            };
                            if on("code") {
                                v = format!("`{v}`");
                            }
                            if on("bold") {
                                v = format!("**{v}**");
                            }
                            if on("italic") {
                                v = format!("*{v}*");
                            }
                            if on("strike") {
                                v = format!("~~{v}~~");
                            }
                            if on("underline") {
                                v = format!("<u>{v}</u>");
                            }
                            if let Some(Any::Map(link)) = a.get("link")
                                && let Some(Any::String(href)) = link.get("href")
                            {
                                let target = href
                                    .rsplit('/')
                                    .next()
                                    .and_then(|id| id.parse().ok())
                                    .and_then(links)
                                    .unwrap_or_else(|| href.to_string());
                                v = format!(
                                    "[{v}]({})",
                                    target.replace(')', "%29").replace('(', "%28")
                                );
                            }
                        }
                        out.push_str(&v);
                    }
                }
            }
            XmlOut::Element(child) if child.tag().as_ref() == "hardBreak" => {
                out.push_str("\\\n");
                line_start = true;
            }
            XmlOut::Element(child) => out.push_str(&inline(&child, txn, links)),
            _ => {}
        }
    }
    out
}

fn render<T: ReadTxn>(
    el: &XmlElementRef,
    txn: &T,
    depth: usize,
    marker: &str,
    links: &dyn Fn(ObjectId) -> Option<String>,
    files: &dyn Fn(ObjectId) -> Option<(String, String)>,
    lines: &mut Vec<String>,
) {
    if depth > 32 {
        return;
    }
    let tag = el.tag();
    match tag.as_ref() {
        "paragraph" | "heading" => {
            let text = inline(el, txn, links);
            if !text.is_empty() {
                let prefix = if tag.as_ref() == "heading" {
                    format!(
                        "{} ",
                        "#".repeat(
                            attr(el, txn, "level")
                                .and_then(|n| n.parse::<usize>().ok())
                                .unwrap_or(1)
                                .clamp(1, 3)
                        )
                    )
                } else {
                    String::new()
                };
                let lead = if marker.is_empty() {
                    prefix
                } else {
                    format!("{marker}{prefix}")
                };
                lines.push(format!("{lead}{text}"));
            }
        }
        "image" => {
            let image = attr(el, txn, "file")
                .and_then(|s| s.parse().ok())
                .and_then(files)
                .map(|(name, path)| {
                    format!("![{}]({})", escape_inline(&name), path.replace(')', "%29"))
                });
            lines.push(format!(
                "{marker}{}",
                image.unwrap_or_else(|| "*[missing image]*".into())
            ));
        }
        "bulletList" | "orderedList" | "taskList" => {
            let start = attr(el, txn, "start")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(1);
            for (index, child) in el.children(txn).enumerate() {
                if let XmlOut::Element(item) = child {
                    let bullet = match tag.as_ref() {
                        "orderedList" => format!("{}. ", start + index),
                        "taskList" => format!(
                            "- [{}] ",
                            if attr(&item, txn, "checked").as_deref() == Some("true") {
                                "x"
                            } else {
                                " "
                            }
                        ),
                        _ => "- ".into(),
                    };
                    let indent =
                        " ".repeat(depth * if tag.as_ref() == "orderedList" { 3 } else { 2 });
                    let mut first = true;
                    for child in item.children(txn) {
                        if let XmlOut::Element(block) = child {
                            let prefix = if first {
                                format!("{indent}{bullet}")
                            } else {
                                String::new()
                            };
                            render(&block, txn, depth + 1, &prefix, links, files, lines);
                            first = false;
                        }
                    }
                }
            }
        }
        "blockquote" => {
            let mut quoted = Vec::new();
            for child in el.children(txn) {
                if let XmlOut::Element(block) = child {
                    render(&block, txn, depth + 1, "", links, files, &mut quoted);
                }
            }
            lines.push(
                quoted
                    .join("\n")
                    .lines()
                    .map(|line| format!("> {line}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
        }
        _ => {
            let children: Vec<_> = el.children(txn).collect();
            if children.iter().any(|c| matches!(c, XmlOut::Text(_))) {
                let text = inline(el, txn, links);
                if !text.is_empty() {
                    lines.push(format!("{marker}{text}"));
                }
            } else {
                for child in children {
                    if let XmlOut::Element(block) = child {
                        render(&block, txn, depth + 1, marker, links, files, lines);
                    }
                }
            }
        }
    }
}

pub(crate) fn to_markdown<T: ReadTxn>(
    fragment: &XmlFragmentRef,
    txn: &T,
    links: &dyn Fn(ObjectId) -> Option<String>,
    files: &dyn Fn(ObjectId) -> Option<(String, String)>,
) -> String {
    let mut blocks = Vec::new();
    for child in fragment.children(txn) {
        if let XmlOut::Element(el) = child {
            let mut lines = Vec::new();
            render(&el, txn, 0, "", links, files, &mut lines);
            if !lines.is_empty() {
                blocks.push(lines.join("\n"));
            }
        }
    }
    if blocks.is_empty() {
        String::new()
    } else {
        format!("{}\n", blocks.join("\n\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yrs::{Doc, Text, Transact, WriteTxn, Xml, XmlElementPrelim, XmlFragment, XmlTextPrelim};

    #[test]
    fn blocks_and_marks_become_markdown() {
        let doc = Doc::new();
        let mut tx = doc.transact_mut();
        let root = tx.get_or_insert_xml_fragment("default");
        let heading = root.push_back(
            &mut tx,
            XmlElementPrelim::new("heading", [XmlTextPrelim::new("Kyoto").into()]),
        );
        heading.insert_attribute(&mut tx, "level", 2);
        let p = root.push_back(&mut tx, XmlElementPrelim::empty("paragraph"));
        let text = p.push_back(&mut tx, XmlTextPrelim::new("Beautiful "));
        let marks: yrs::types::Attrs = [
            ("bold".into(), yrs::Any::Bool(true)),
            ("italic".into(), yrs::Any::Bool(true)),
        ]
        .into();
        text.insert_with_attributes(&mut tx, 10, "city", marks);
        let list = root.push_back(&mut tx, XmlElementPrelim::empty("orderedList"));
        list.insert_attribute(&mut tx, "start", 3);
        list.push_back(
            &mut tx,
            XmlElementPrelim::new(
                "listItem",
                [
                    XmlElementPrelim::new("paragraph", [XmlTextPrelim::new("Temple").into()])
                        .into(),
                ],
            ),
        );
        assert_eq!(
            to_markdown(&root, &tx, &|_| None, &|_| None),
            "## Kyoto\n\nBeautiful ***city***\n\n3. Temple\n"
        );
    }

    #[test]
    fn nested_bullets_checked_tasks_quotes_and_hard_breaks() {
        let doc = Doc::new();
        let mut tx = doc.transact_mut();
        let root = tx.get_or_insert_xml_fragment("default");
        let list = root.push_back(&mut tx, XmlElementPrelim::empty("bulletList"));
        let item = list.push_back(&mut tx, XmlElementPrelim::empty("listItem"));
        item.push_back(
            &mut tx,
            XmlElementPrelim::new("paragraph", [XmlTextPrelim::new("First").into()]),
        );
        let nested = item.push_back(&mut tx, XmlElementPrelim::empty("bulletList"));
        nested.push_back(
            &mut tx,
            XmlElementPrelim::new(
                "listItem",
                [XmlElementPrelim::new("paragraph", [XmlTextPrelim::new("Child").into()]).into()],
            ),
        );
        let tasks = root.push_back(&mut tx, XmlElementPrelim::empty("taskList"));
        let task = tasks.push_back(
            &mut tx,
            XmlElementPrelim::new(
                "taskItem",
                [XmlElementPrelim::new("paragraph", [XmlTextPrelim::new("Done").into()]).into()],
            ),
        );
        task.insert_attribute(&mut tx, "checked", true);
        let quote = root.push_back(&mut tx, XmlElementPrelim::empty("blockquote"));
        let paragraph = quote.push_back(&mut tx, XmlElementPrelim::empty("paragraph"));
        paragraph.push_back(&mut tx, XmlTextPrelim::new("Line one"));
        paragraph.push_back(&mut tx, XmlElementPrelim::empty("hardBreak"));
        paragraph.push_back(&mut tx, XmlTextPrelim::new("Line two"));
        assert_eq!(
            to_markdown(&root, &tx, &|_| None, &|_| None),
            "- First\n  - Child\n\n- [x] Done\n\n> Line one\\\n> Line two\n"
        );
    }

    #[test]
    fn text_that_looks_like_markdown_is_escaped() {
        let doc = Doc::new();
        let mut tx = doc.transact_mut();
        let root = tx.get_or_insert_xml_fragment("default");
        root.push_back(
            &mut tx,
            XmlElementPrelim::new(
                "paragraph",
                [XmlTextPrelim::new("*not bold* # 1. [x]").into()],
            ),
        );
        assert_eq!(
            to_markdown(&root, &tx, &|_| None, &|_| None),
            "\\*not bold\\* # 1. \\[x\\]\n"
        );
    }

    #[test]
    fn a_list_or_heading_marker_at_the_start_of_a_line_is_escaped() {
        let doc = Doc::new();
        let mut tx = doc.transact_mut();
        let root = tx.get_or_insert_xml_fragment("default");
        for text in [
            "1. buy milk",
            "- a dash",
            "> a quote",
            "# a heading",
            "plain 1. later",
        ] {
            root.push_back(
                &mut tx,
                XmlElementPrelim::new("paragraph", [XmlTextPrelim::new(text).into()]),
            );
        }
        assert_eq!(
            to_markdown(&root, &tx, &|_| None, &|_| None),
            "1\\. buy milk\n\n\\- a dash\n\n\\> a quote\n\n\\# a heading\n\nplain 1. later\n"
        );
    }

    #[test]
    fn a_link_to_a_note_uses_its_relative_markdown_path() {
        let doc = Doc::new();
        let mut tx = doc.transact_mut();
        let root = tx.get_or_insert_xml_fragment("default");
        let p = root.push_back(&mut tx, XmlElementPrelim::empty("paragraph"));
        let text = p.push_back(&mut tx, XmlTextPrelim::new("See "));
        let id = ObjectId([6; 16]);
        let link: yrs::types::Attrs = [(
            "link".into(),
            yrs::Any::Map(
                [(
                    "href".to_string(),
                    yrs::Any::String(format!("bh://notes/{id}").into()),
                )]
                .into_iter()
                .collect::<std::collections::HashMap<_, _>>()
                .into(),
            ),
        )]
        .into();
        text.insert_with_attributes(&mut tx, 4, "Ferry", link);
        assert_eq!(
            to_markdown(
                &root,
                &tx,
                &|found| (found == id).then(|| "../Ferry.md".into()),
                &|_| None
            ),
            "See [Ferry](../Ferry.md)\n"
        );
    }

    #[test]
    fn note_links_and_images_become_relative_paths() {
        let doc = Doc::new();
        let id = ObjectId([7; 16]);
        let mut tx = doc.transact_mut();
        let root = tx.get_or_insert_xml_fragment("default");
        let image = root.push_back(&mut tx, XmlElementPrelim::empty("image"));
        image.insert_attribute(&mut tx, "file", id.to_string());
        assert_eq!(
            to_markdown(&root, &tx, &|_| None, &|key| (key == id)
                .then(|| ("photo".into(), "Kyoto/photo.png".into()))),
            "![photo](Kyoto/photo.png)\n"
        );
    }
}
