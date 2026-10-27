//! Bounded, permission-checked local tools for Hero.
use super::{access::Access, chat::write_note_body};
use crate::{Base, BaseId, Error, FieldKind, NewObject, ObjectId, ObjectSummary, TypeRef};
use bh_models::{ToolCall, ToolSpec};
use serde_json::{Value, json};

const MAX_RESULT: usize = 16 * 1024;

pub(crate) struct Tools {
    chat: Base,
    others: Vec<(Base, Access)>,
    project: Option<ObjectId>,
}
pub(crate) struct ToolResult {
    pub content: String,
    pub step: super::Step,
    pub ask: Option<BaseId>,
    pub created: Option<ObjectId>,
}
impl Tools {
    pub(crate) fn new(
        chat_base: Base,
        others: Vec<(Base, Access)>,
        project: Option<ObjectId>,
    ) -> Self {
        Self {
            chat: chat_base,
            others,
            project,
        }
    }

    pub(crate) fn specs() -> Vec<ToolSpec> {
        [
            ("list_bases", "List bases and types available to this chat.", json!({"type":"object","properties":{}})),
            ("list", "List objects under a parent in an accessible base.", json!({"type":"object","properties":{"base":{"type":"string"},"parent":{"type":"string"},"type":{"type":"string"},"limit":{"type":"integer","maximum":200}}})),
            ("read", "Read a note or record in an accessible base.", json!({"type":"object","properties":{"base":{"type":"string"},"id":{"type":"string"}},"required":["id"]})),
            ("search", "Search notes and records in accessible bases.", json!({"type":"object","properties":{"text":{"type":"string"},"base":{"type":"string"},"limit":{"type":"integer","maximum":20}},"required":["text"]})),
            ("create_note", "Create a new note in this chat's base.", json!({"type":"object","properties":{"title":{"type":"string"},"text":{"type":"string"},"parent":{"type":"string"}},"required":["title","text"]})),
        ].into_iter().map(|(name, description, parameters)| ToolSpec {name:name.into(),description:description.into(),parameters}).collect()
    }

    pub(crate) fn call(&mut self, call: &ToolCall) -> ToolResult {
        let base_arg = serde_json::from_str::<Value>(&call.arguments)
            .ok()
            .filter(Value::is_object);
        let selected = base_arg
            .as_ref()
            .and_then(|a| a.get("base"))
            .and_then(Value::as_str)
            .and_then(|s| s.parse().ok());
        let mut step = super::Step {
            tool: call.name.clone(),
            base: selected,
            object: None,
            title: None,
        };
        let mut ask = None;
        let mut created = None;
        let outcome = (|| -> Result<Value, &'static str> {
            let args = base_arg.as_ref().ok_or("invalid")?;
            if call.name != "create_note" && args.get("base").is_some() && selected.is_none() {
                return Err("invalid");
            }
            let choose = || -> Result<&Base, &'static str> {
                match selected {
                    None => Ok(&self.chat),
                    Some(id) if id == self.chat.id() => Ok(&self.chat),
                    Some(id) => match self.others.iter().find(|(b, _)| b.id() == id) {
                        Some((b, Access::Free)) => Ok(b),
                        Some((_, Access::Ask)) => Err("needs_permission"),
                        Some((_, Access::Never)) => Err("not_allowed"),
                        None => Err("not_found"),
                    },
                }
            };
            match call.name.as_str() {
                "list_bases" => {
                    let mut out = Vec::new();
                    for (base, access) in std::iter::once((&self.chat, Access::Free))
                        .chain(self.others.iter().map(|(b, a)| (b, *a)))
                    {
                        if access == Access::Never {
                            continue;
                        }
                        let types: Vec<Value> = base
                            .types()
                            .map_err(code)?
                            .iter()
                            .map(|t| json!({"name":t.name,"doc":t.doc}))
                            .collect();
                        out.push(json!({"base":base.id(),"name":base.name(),"current":base.id()==self.chat.id(),"access":if access == Access::Ask {"ask"} else {"free"},"types":types}));
                    }
                    Ok(Value::Array(out))
                }
                "list" => {
                    let base = choose()?;
                    let parent = optional_id(args, "parent")?;
                    let limit = limit(args, 200, 50)?;
                    let ty = args
                        .get("type")
                        .map(|v| v.as_str().ok_or("invalid"))
                        .transpose()?;
                    let mut items = Vec::new();
                    let mut more = false;
                    for s in base
                        .children(parent)
                        .map_err(code)?
                        .into_iter()
                        .filter(|s| visible(s) && ty.is_none_or(|t| s.ty.name == t))
                    {
                        if items.len() == limit {
                            more = true;
                            break;
                        }
                        items.push(json!({"id":s.id,"type":s.ty.name,"title":safe_title(base,&s),"updatedAt":s.updated_at}));
                    }
                    Ok(json!({"items":items,"more":more}))
                }
                "read" => {
                    let base = choose()?;
                    let id = required_id(args, "id")?;
                    let s = base
                        .get(id)
                        .map_err(code)?
                        .filter(visible)
                        .ok_or("not_found")?;
                    step.object = Some(id);
                    step.title = Some(safe_title(base, &s));
                    let text = if s.ty.name == "core.note" {
                        base.note(id).map_err(code)?.text()
                    } else {
                        String::new()
                    };
                    let (text, truncated) = cut(&text, 20_000, 12_000);
                    let mut fields = s.fields;
                    // File keys remain secret even before the file type is installed.
                    if s.ty.name == "core.file" {
                        fields.remove("key");
                    }
                    if let Some(def) = definition(base, &s.ty) {
                        for f in def.fields {
                            if f.kind == FieldKind::Secret {
                                fields.remove(&f.name);
                            }
                        }
                    } else {
                        // Fetched records may arrive before their definitions. Their
                        // fields have no known classification yet, so expose none.
                        fields.clear();
                    }
                    Ok(
                        json!({"id":id,"type":s.ty.name,"title":step.title,"text":text,"fields":fields,"truncated":truncated}),
                    )
                }
                "search" => {
                    let text = args.get("text").and_then(Value::as_str).ok_or("invalid")?;
                    let limit = limit(args, 20, 20)?;
                    let bases: Vec<&Base> = if selected.is_some() {
                        vec![choose()?]
                    } else {
                        std::iter::once(&self.chat)
                            .chain(
                                self.others
                                    .iter()
                                    .filter(|(_, a)| *a == Access::Free)
                                    .map(|(b, _)| b),
                            )
                            .collect()
                    };
                    let mut hits = Vec::new();
                    for base in bases {
                        for hit in base.search(text, limit).map_err(code)? {
                            if hits.len() == limit {
                                break;
                            }
                            if secret_title(base, &hit.ty) {
                                continue;
                            }
                            hits.push(json!({"base":base.id(),"id":hit.id,"title":hit.title,"snippet":hit.snippet}));
                        }
                    }
                    Ok(json!({"hits":hits}))
                }
                "create_note" => {
                    let title = args
                        .get("title")
                        .and_then(Value::as_str)
                        .filter(|s| !s.trim().is_empty())
                        .ok_or("invalid")?;
                    let text = args.get("text").and_then(Value::as_str).ok_or("invalid")?;
                    let parent = optional_id(args, "parent")?.or(self.project);
                    let id = self
                        .chat
                        .create(NewObject {
                            ty: TypeRef::new("core.note", 1),
                            parent,
                            after: None,
                            fields: Default::default(),
                        })
                        .map_err(code)?;
                    // Keep the created ID even if editing the fresh note fails.
                    created = Some(id);
                    write_note_body(&self.chat.note(id).map_err(code)?, title, text)
                        .map_err(code)?;
                    step.object = Some(id);
                    step.title = Some(title.chars().take(200).collect());
                    Ok(json!({"id":id}))
                }
                _ => Err("invalid"),
            }
        })();
        if outcome == Err("needs_permission") {
            ask = selected;
        }
        let value = outcome.unwrap_or_else(|error| json!({"error":error}));
        let content = bounded(value);
        ToolResult {
            content,
            step,
            ask,
            created,
        }
    }
}

fn visible(s: &ObjectSummary) -> bool {
    !s.deleted
        && !matches!(
            s.ty.name.as_str(),
            "core.chat" | "core.message" | "core.type" | "core.base"
        )
}
fn definition(base: &Base, ty: &TypeRef) -> Option<crate::TypeDef> {
    crate::types::core_def(ty).or_else(|| {
        base.types()
            .ok()?
            .into_iter()
            .find(|d| d.name == ty.name && d.version == ty.version)
    })
}
fn secret_title(base: &Base, ty: &TypeRef) -> bool {
    definition(base, ty).is_some_and(|d| {
        d.title_field.is_some_and(|field| {
            d.fields
                .iter()
                .any(|f| f.name == field && f.kind == FieldKind::Secret)
        })
    })
}
fn safe_title(base: &Base, s: &ObjectSummary) -> String {
    if secret_title(base, &s.ty) {
        String::new()
    } else {
        s.title.clone()
    }
}
fn optional_id(args: &Value, key: &str) -> Result<Option<ObjectId>, &'static str> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => s.parse().map(Some).map_err(|_| "invalid"),
        _ => Err("invalid"),
    }
}
fn required_id(args: &Value, key: &str) -> Result<ObjectId, &'static str> {
    optional_id(args, key)?.ok_or("invalid")
}
fn limit(args: &Value, max: usize, default: usize) -> Result<usize, &'static str> {
    match args.get("limit") {
        None => Ok(default),
        Some(v) => usize::try_from(v.as_u64().ok_or("invalid")?)
            .ok()
            .filter(|n| *n <= max)
            .ok_or("invalid"),
    }
}
fn code(error: Error) -> &'static str {
    match error {
        Error::NotFound => "not_found",
        Error::ReadOnly => "read_only",
        Error::Forbidden => "not_allowed",
        _ => "invalid",
    }
}
fn cut(text: &str, max_chars: usize, max_bytes: usize) -> (String, bool) {
    let mut end = 0;
    for (count, c) in text.chars().enumerate() {
        if count == max_chars || end + c.len_utf8() > max_bytes {
            break;
        }
        end += c.len_utf8();
    }
    (text[..end].to_owned(), end < text.len())
}
fn bounded(mut value: Value) -> String {
    // Shrink payloads without ever returning a partial JSON document.
    loop {
        let result = value.to_string();
        if result.len() <= MAX_RESULT {
            return result;
        }
        if let Some(fields) = value.get_mut("fields").and_then(Value::as_object_mut)
            && !fields.is_empty()
        {
            if let Some(key) = fields.keys().next_back().cloned() {
                fields.remove(&key);
            }
            value["truncated"] = json!(true);
        } else if let Some(text) = value.get("text").and_then(Value::as_str)
            && !text.is_empty()
        {
            let len = text.len() / 2;
            let end = text
                .char_indices()
                .map(|(i, _)| i)
                .take_while(|i| *i <= len)
                .last()
                .unwrap_or(0);
            let shortened = text[..end].to_owned();
            value["text"] = json!(shortened);
            value["truncated"] = json!(true);
        } else if let Some(items) = value.get_mut("items").and_then(Value::as_array_mut)
            && !items.is_empty()
        {
            items.pop();
            value["more"] = json!(true);
        } else if let Some(hits) = value.get_mut("hits").and_then(Value::as_array_mut)
            && !hits.is_empty()
        {
            hits.pop();
        } else if let Some(list) = value.as_array_mut()
            && !list.is_empty()
        {
            list.pop();
        } else {
            return json!({"error":"invalid"}).to_string();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FieldDef, FieldKind, NewObject, TypeDef, TypeRef};
    use serde_json::{Value, json};
    fn base() -> Base {
        Base::open_local(
            tempfile::tempdir().unwrap().path(),
            bh_crypto::random::<32>(),
        )
        .unwrap()
    }
    fn make(base: &Base, ty: &str, fields: Value, parent: Option<ObjectId>) -> ObjectId {
        base.create(NewObject {
            ty: TypeRef::new(ty, 1),
            parent,
            after: None,
            fields: fields.as_object().unwrap().clone(),
        })
        .unwrap()
    }
    fn call(tools: &mut Tools, name: &str, args: Value) -> ToolResult {
        tools.call(&ToolCall {
            id: "1".into(),
            name: name.into(),
            arguments: args.to_string(),
        })
    }
    fn output(result: &ToolResult) -> Value {
        serde_json::from_str(&result.content).unwrap()
    }
    #[test]
    fn create_note_writes_only_into_the_chat_base() {
        let chat = base();
        let health = base();
        let mut tools = Tools::new(chat.clone(), vec![(health.clone(), Access::Free)], None);
        let result = call(
            &mut tools,
            "create_note",
            json!({"base": health.id(), "title":"Packing list", "text":"Ferry"}),
        );
        let id = result.created.unwrap();
        assert!(chat.get(id).unwrap().is_some());
        assert!(health.get(id).unwrap().is_none());
        assert_eq!(output(&result)["id"], id.to_string());
    }
    #[test]
    fn an_ask_base_returns_no_content() {
        let chat = base();
        let personal = base();
        let id = make(
            &personal,
            "core.folder",
            json!({"name":"Private title"}),
            None,
        );
        let mut tools = Tools::new(chat, vec![(personal.clone(), Access::Ask)], None);
        for (name, args) in [
            ("read", json!({"base":personal.id(),"id":id})),
            ("list", json!({"base":personal.id()})),
            ("search", json!({"base":personal.id(),"text":"Private"})),
        ] {
            let result = call(&mut tools, name, args);
            assert_eq!(output(&result), json!({"error":"needs_permission"}));
            assert_eq!(result.ask, Some(personal.id()));
            assert!(!result.content.contains("Private title"));
        }
    }
    #[test]
    fn search_without_a_base_covers_only_free_bases() {
        let chat = base();
        let personal = base();
        let chat_id = make(&chat, "core.folder", json!({"name":"ferry chat"}), None);
        make(
            &personal,
            "core.folder",
            json!({"name":"ferry private"}),
            None,
        );
        let mut tools = Tools::new(chat, vec![(personal, Access::Ask)], None);
        let result = call(&mut tools, "search", json!({"text":"ferry"}));
        assert_eq!(output(&result)["hits"].as_array().unwrap().len(), 1);
        assert_eq!(output(&result)["hits"][0]["id"], chat_id.to_string());
    }
    #[test]
    fn reading_a_huge_note_is_cut_to_20000_characters() {
        let chat = base();
        let mut tools = Tools::new(chat.clone(), vec![], None);
        let id = make(&chat, "core.note", json!({}), None);
        super::super::chat::write_note_body(
            &chat.note(id).unwrap(),
            "Huge",
            &"x".repeat(5_000_000),
        )
        .unwrap();
        let result = call(&mut tools, "read", json!({"id":id}));
        let value = output(&result);
        assert!(value["text"].as_str().unwrap().chars().count() <= 20_000);
        assert_eq!(value["truncated"], true);
        assert!(result.content.len() <= 16 * 1024);
    }
    #[test]
    fn chats_and_messages_are_invisible_to_tools() {
        let chat = base();
        let id = make(&chat, "core.chat", json!({"title":"ferry chat"}), None);
        make(
            &chat,
            "core.message",
            json!({"role":"hero","at":"2026-10-26T00:00:00Z","state":"done","text":"ferry"}),
            Some(id),
        );
        let mut tools = Tools::new(chat.clone(), vec![], None);
        assert!(
            output(&call(&mut tools, "list", json!({})))["items"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            output(&call(&mut tools, "search", json!({"text":"ferry"})))["hits"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            output(&call(&mut tools, "read", json!({"id":id}))),
            json!({"error":"not_found"})
        );
    }
    #[test]
    fn secret_fields_are_omitted_from_tool_output() {
        let chat = base();
        chat.define_type(TypeDef {
            name: "demo.secret".into(),
            version: 1,
            doc: "test".into(),
            title_field: Some("name".into()),
            fields: vec![
                FieldDef {
                    name: "name".into(),
                    kind: FieldKind::Text,
                    required: false,
                    unit: None,
                    doc: String::new(),
                },
                FieldDef {
                    name: "token".into(),
                    kind: FieldKind::Secret,
                    required: false,
                    unit: None,
                    doc: String::new(),
                },
            ],
        })
        .unwrap();
        let id = make(
            &chat,
            "demo.secret",
            json!({"name":"Safe", "token":"private-file-key-marker"}),
            None,
        );
        let mut tools = Tools::new(chat, vec![], None);
        let result = call(&mut tools, "read", json!({"id":id}));
        assert!(output(&result)["fields"].get("token").is_none());
        assert!(!result.content.contains("private-file-key-marker"));
    }
    #[test]
    fn record_arriving_before_its_definition_never_exposes_secret_fields() {
        use crate::objects;
        use yrs::{Doc, Transact as _};

        let chat = base();
        let id = ObjectId([42; 16]);
        let doc = Doc::new();
        let update = {
            let mut txn = doc.transact_mut();
            objects::write_type(&mut txn, &TypeRef::new("demo.late", 1));
            objects::write_place(&mut txn, None, "V");
            objects::write_fields(
                &mut txn,
                &json!({"name":"Public name", "token":"private-file-key-marker"})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap();
            txn.encode_update_v1()
        };
        chat.test_apply_remote(id, &update).unwrap();
        let mut tools = Tools::new(chat.clone(), vec![], None);
        let before = call(&mut tools, "read", json!({"id":id}));
        assert_eq!(output(&before)["fields"], json!({}));
        assert_eq!(output(&before)["title"], "");
        assert!(!before.content.contains("private-file-key-marker"));
        assert!(
            !call(&mut tools, "list", json!({}))
                .content
                .contains("private-file-key-marker")
        );
        assert!(
            !call(
                &mut tools,
                "search",
                json!({"text":"private-file-key-marker"})
            )
            .content
            .contains("private-file-key-marker")
        );

        chat.define_type(TypeDef {
            name: "demo.late".into(),
            version: 1,
            doc: String::new(),
            title_field: Some("name".into()),
            fields: vec![
                FieldDef {
                    name: "name".into(),
                    kind: FieldKind::Text,
                    required: false,
                    unit: None,
                    doc: String::new(),
                },
                FieldDef {
                    name: "token".into(),
                    kind: FieldKind::Secret,
                    required: false,
                    unit: None,
                    doc: String::new(),
                },
            ],
        })
        .unwrap();
        let after = call(&mut tools, "read", json!({"id":id}));
        assert_eq!(output(&after)["fields"], json!({"name":"Public name"}));
        assert_eq!(output(&after)["title"], "Public name");
        assert!(!after.content.contains("private-file-key-marker"));
    }
    #[test]
    fn secret_values_do_not_escape_through_list_or_search() {
        let chat = base();
        chat.define_type(TypeDef {
            name: "demo.hidden_title".into(),
            version: 1,
            doc: String::new(),
            title_field: Some("name".into()),
            fields: vec![
                FieldDef {
                    name: "name".into(),
                    kind: FieldKind::Text,
                    required: false,
                    unit: None,
                    doc: String::new(),
                },
                FieldDef {
                    name: "token".into(),
                    kind: FieldKind::Secret,
                    required: false,
                    unit: None,
                    doc: String::new(),
                },
            ],
        })
        .unwrap();
        let id = make(
            &chat,
            "demo.hidden_title",
            json!({"name":"Safe", "token":"private-file-key-marker"}),
            None,
        );
        let mut tools = Tools::new(chat, vec![], None);
        for (name, args) in [
            ("read", json!({"id":id})),
            ("list", json!({})),
            ("search", json!({"text":"private-file-key-marker"})),
        ] {
            assert!(
                !call(&mut tools, name, args)
                    .content
                    .contains("private-file-key-marker")
            );
        }
    }
    #[test]
    fn create_note_defaults_to_the_chat_project() {
        let chat = base();
        let project = make(&chat, "core.project", json!({"name":"Journey"}), None);
        let mut tools = Tools::new(chat.clone(), vec![], Some(project));
        let id = call(
            &mut tools,
            "create_note",
            json!({"title":"Packing list", "text":"One\nTwo\nThree"}),
        )
        .created
        .unwrap();
        assert_eq!(chat.get(id).unwrap().unwrap().parent, Some(project));
        assert_eq!(chat.get(id).unwrap().unwrap().title, "Packing list");
        assert_eq!(
            chat.note(id).unwrap().text(),
            "Packing list\nOne\nTwo\nThree"
        );
    }
    #[test]
    fn malformed_arguments_are_an_invalid_result_not_a_panic() {
        let mut tools = Tools::new(base(), vec![], None);
        let result = tools.call(&ToolCall {
            id: "1".into(),
            name: "read".into(),
            arguments: "{".into(),
        });
        assert_eq!(output(&result), json!({"error":"invalid"}));
    }
}
