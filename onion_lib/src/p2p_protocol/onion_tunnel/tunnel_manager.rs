use crate::p2p_protocol::onion_tunnel::{OnionTunnel, TunnelStatus};
use crate::p2p_protocol::{ConnectionId, TunnelId};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

static ID_COUNTER: AtomicU32 = AtomicU32::new(1);

type AvailableForNextRound = bool;

pub(crate) struct TunnelManager {
    tunnel_registry: HashMap<TunnelId, (OnionTunnel, AvailableForNextRound)>,
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
        log::trace!("Tunnel Manager: Insert tunnel with id={:?}", tunnel_id);
        let _ = self.tunnel_registry.insert(tunnel_id, (onion_tunnel, true));
    }

    pub(crate) fn remove_tunnel(&mut self, tunnel_id: &TunnelId) {
        log::trace!("Tunnel Manager: Remove tunnel with id={:?}", tunnel_id);
        let _ = self.tunnel_registry.remove(tunnel_id);
        self.remove_redirection_link(tunnel_id);
    }

    pub(crate) fn get_tunnel(&self, tunnel_id: &TunnelId) -> Option<&OnionTunnel> {
        self.tunnel_registry
            .get(tunnel_id)
            .map(|(tunnel, _)| tunnel)
    }

    pub(crate) fn set_connected(&mut self, tunnel_id: &TunnelId, cover_only: bool) {
        if let Some((tunnel, _)) = self.tunnel_registry.get_mut(tunnel_id) {
            log::trace!(
                "Tunnel Manager: Mark tunnel with id={:?} as connected",
                tunnel_id
            );
            tunnel.status = if cover_only {
                TunnelStatus::Downgraded
            } else {
                TunnelStatus::Connected
            };
        }
    }

    pub(crate) fn downgrade_tunnel(&mut self, tunnel_id: &TunnelId) {
        if let Some((tunnel, _)) = self.tunnel_registry.get_mut(tunnel_id) {
            log::trace!(
                "Tunnel Manager: Mark tunnel with id={:?} as downgraded",
                tunnel_id
            );
            tunnel.status = TunnelStatus::Downgraded;
        }
    }

    pub(crate) fn get_connected_initiator_tunnel_ids(&self) -> Vec<TunnelId> {
        self.tunnel_registry
            .iter()
            .filter(|(_, (tunnel, _))| tunnel.is_initiator() && tunnel.is_connected())
            .map(|(id, _)| *id)
            .collect()
    }

    pub(crate) fn add_redirection_link(&mut self, id_old: TunnelId, id_new: TunnelId) {
        // check if there is already a link, which means that the original tunnel has been updated already
        let origin_id = match self.reverse_links.get(&id_old) {
            None => {
                // mapping not available yet
                id_old
            }
            Some(origin_id) => {
                // mapping available yet
                // we have to ensure that the old reverse link stays until the tunnel is removed
                *origin_id
            }
        };
        log::trace!(
            "Tunnel Manager: Add reverse link <{:?}, {:?}>",
            id_new,
            origin_id
        );
        let _ = self.reverse_links.insert(id_new, origin_id);
        log::trace!("Tunnel Manager: Add link <{:?}, {:?}>", origin_id, id_new);
        let _ = self
            .links
            .entry(origin_id)
            .and_modify(|e| *e = id_new)
            .or_insert(id_new);
        assert_eq!(
            self.links.get_key_value(&origin_id).unwrap(),
            (&origin_id, &id_new)
        );
        assert_eq!(
            self.reverse_links.get_key_value(&id_new).unwrap(),
            (&id_new, &origin_id)
        );
    }

    pub(crate) fn remove_redirection_link(&mut self, tunnel_id: &TunnelId) {
        if let Some(old_id) = self.reverse_links.remove(tunnel_id) {
            log::trace!(
                "Tunnel Manager: Remove reverse link <{:?}, {:?}>",
                tunnel_id,
                old_id
            );
            // only remove link if it points to the tunnel_id, otherwise we are removing a tunnel that
            // has been rebuilt but we dont want to remove the link for the new tunnel
            let remove_link = if let Some(link_v) = self.reverse_links.get(&old_id) {
                link_v == tunnel_id
            } else {
                false
            };
            if remove_link {
                log::trace!(
                    "Tunnel Manager: Remove link <{:?}, {:?}>",
                    old_id,
                    tunnel_id
                );
                let _ = self.links.remove(&old_id);
            }
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
        let mut downgrades = vec![];
        for (id, (tunnel, _)) in self.tunnel_registry.iter_mut() {
            if tunnel.unsubscribe(connection_id).await {
                downgrades.push(*id);
            }
        }
        for id in downgrades {
            self.downgrade_tunnel(&id);
        }
    }

    pub(crate) async fn round_cleanup(&mut self) {
        // shutdown all active tunnels from the previous round
        for (id, (tunnel, next_round)) in self.tunnel_registry.iter_mut() {
            if *next_round {
                log::trace!("Tunnel={:?}: New tunnel, skip cleanup", id);
                *next_round = false;
            } else {
                log::trace!("Tunnel={:?}: Shutdown triggered by round cleanup", id);
                tunnel.shutdown_tunnel().await;
            }
        }
    }
}
