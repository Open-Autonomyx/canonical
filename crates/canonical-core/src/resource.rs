//! Resource addressing: "<ownerId>:<path>". The owner is everything before the
//! first colon (identity ids are base64url and contain no colon). A path may end
//! in "/*" for a subtree; "*" is everything.

pub fn make_resource(owner_id: &str, path: &str) -> String {
    format!("{owner_id}:{path}")
}

pub fn resource_owner(resource: &str) -> &str {
    match resource.find(':') {
        Some(i) => &resource[..i],
        None => resource,
    }
}

pub fn resource_path(resource: &str) -> &str {
    match resource.find(':') {
        Some(i) => &resource[i + 1..],
        None => "",
    }
}

pub fn path_subsumes(parent: &str, child: &str) -> bool {
    if parent == child || parent == "*" {
        return true;
    }
    if parent.ends_with("/*") {
        // "a/b/*" -> the child must stay within "a/b/" (keep the separator, so
        // "tool/*" does not also cover a sibling like "toolbox/secret").
        let prefix = &parent[..parent.len() - 1];
        return child.starts_with(prefix);
    }
    false
}

pub fn resource_subsumes(parent: &str, child: &str) -> bool {
    resource_owner(parent) == resource_owner(child)
        && path_subsumes(resource_path(parent), resource_path(child))
}

pub fn action_subsumes(parent: &str, child: &str) -> bool {
    parent == "*" || parent == child
}
