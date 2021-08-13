use crate::p2p_protocol::onion_tunnel::{OnionTunnel, TunnelStatus};
use crate::p2p_protocol::{ConnectionId, TunnelId};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

static ID_COUNTER: AtomicU32 = AtomicU32::new(1);

pub(crate) struct TunnelManager {
    tunnel_registry: HashMap<TunnelId, OnionTunnel>,
    links: HashMap<TunnelId, TunnelId>, // old_tunnel_ids to new_tunnel_ids
    reverse_links: HashMap<TunnelId, TunnelId>, // new_tunnel_ids to old_tunnel_ids
}

impl TunnelManager {
    pub(crate) fn new() -> TunnelManager {
        TunnelManager {
            tunnel_registry: HashMap::new(),
            links: HashMap::new(),
            reverse_links: HashMap::new(),
        }
    }

    pub(crate) fn get_id() -> u32 {
        ID_COUNTER.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) fn insert_tunnel(&mut self, tunnel_id: TunnelId, onion_tunnel: OnionTunnel) {
        let _ = self.tunnel_registry.insert(tunnel_id, onion_tunnel);
    }

    pub(crate) fn remove_tunnel(&mut self, tunnel_id: &TunnelId) {
        let _ = self.tunnel_registry.remove(tunnel_id);
    }

    pub(crate) fn get_tunnel(&self, tunnel_id: &TunnelId) -> Option<&OnionTunnel> {
        self.tunnel_registry.get(tunnel_id)
    }

    pub(crate) fn set_connected(&mut self, tunnel_id: &TunnelId) {
        if let Some(tunnel) = self.tunnel_registry.get_mut(tunnel_id) {
            tunnel.status = TunnelStatus::Connected;
        }
    }

    pub(crate) fn add_redirection_link(&mut self, id_old: TunnelId, id_new: TunnelId) {
        // check if there is already a link, which means that the original tunnel has been updated already
        let origin_id = match self.reverse_links.remove(&id_old) {
            None => {
                // mapping not available yet
                self.reverse_links.insert(id_new, id_old).unwrap();
                id_old
            }
            Some(origin_id) => {
                // mapping available yet
                self.reverse_links.insert(id_new, origin_id).unwrap();
                origin_id
            }
        };
        let _ = self
            .links
            .entry(origin_id)
            .and_modify(|e| *e = id_new)
            .or_insert(id_new);
    }

    pub(crate) fn remove_redirection_link(&mut self, tunnel_id: &TunnelId) {
        if let Some(old_id) = self.reverse_links.remove(tunnel_id) {
            let _ = self.links.remove(&old_id);
        }
    }

    pub(crate) fn resolve_tunnel_id(&self, tunnel_id: TunnelId) -> TunnelId {
        match self.links.get(&tunnel_id) {
            None => tunnel_id,
            Some(redirected_id) => *redirected_id,
        }
    }

    pub(crate) fn resolve_reverse_tunnel_id(&self, tunnel_id: TunnelId) -> TunnelId {
        match self.reverse_links.get(&tunnel_id) {
            None => tunnel_id,
            Some(redirected_id) => *redirected_id,
        }
    }

    pub(crate) async fn unsubscribe(&mut self, connection_id: ConnectionId) {
        for (_, tunnel) in self.tunnel_registry.iter_mut() {
            tunnel.unsubscribe(connection_id).await;
        }
    }
}
