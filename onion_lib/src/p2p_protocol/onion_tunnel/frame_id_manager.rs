use crate::p2p_protocol::{Direction, FrameId, TunnelId};
use std::collections::hash_map::Entry;
use std::collections::HashMap;

#[derive(Debug)]
pub struct FrameIdManager {
    frame_ids: HashMap<FrameId, (TunnelId, Direction)>,
    used_frame_ids: HashMap<TunnelId, Vec<(FrameId, Direction)>>,
    ref_ids: HashMap<TunnelId, FrameId>,
}

impl FrameIdManager {
    pub fn new() -> Self {
        Self {
            frame_ids: HashMap::new(),
            used_frame_ids: HashMap::new(),
            ref_ids: HashMap::new(),
        }
    }

    pub fn new_frame_id(&mut self, tunnel_id: TunnelId, direction: Direction) -> FrameId {
        let mut new_id: u64 = rand::random();
        while new_id < 2 || self.frame_ids.contains_key(&new_id) {
            new_id = rand::random();
        }
        log::trace!(
            "Register new frame_id mapping: <{:?},{:?}>",
            new_id,
            (tunnel_id, direction)
        );
        let _ = self.frame_ids.insert(new_id, (tunnel_id, direction));

        // update used_frame_ids
        match self.used_frame_ids.entry(tunnel_id) {
            Entry::Occupied(o) => {
                o.into_mut().push((new_id, direction));
            }
            Entry::Vacant(v) => {
                v.insert(vec![(new_id, direction)]);
            }
        }
        new_id
    }

    pub fn new_frame_ids(
        &mut self,
        tunnel_id: TunnelId,
        direction: Direction,
        count: usize,
    ) -> Vec<FrameId> {
        let mut v = vec![];
        for _ in 0..count {
            v.push(self.new_frame_id(tunnel_id, direction))
        }
        v
    }

    pub fn get_tunnel_id(&self, frame_id: &FrameId) -> Option<(TunnelId, Direction)> {
        self.frame_ids.get(frame_id).map(|(a, b)| (*a, *b))
    }

    pub fn tunnel_closure(&mut self, tunnel_id: TunnelId) {
        // remove all frame_ids for this tunnel
        if let Some(frames) = self.used_frame_ids.remove(&tunnel_id) {
            for (frame_id, d) in frames.iter() {
                log::trace!(
                    "Unregister frame_id mapping <{:?},{:?}>",
                    frame_id,
                    (tunnel_id, d)
                );
                let _ = self.frame_ids.remove(frame_id);
            }
        }
        let _ = self.ref_ids.remove(&tunnel_id);
    }

    pub fn remove_backward_frame_ids(&mut self, tunnel_id: TunnelId) {
        // remove unnecessary frame_ids from registry
        if let Some(frames) = self.used_frame_ids.get_mut(&tunnel_id) {
            // get the backward frame ids
            let backward_frames: Vec<FrameId> = frames
                .iter()
                .filter(|(_, direction)| *direction == Direction::Backward)
                .map(|(id, _)| *id)
                .collect();
            // remove backward frame ids from tunnel -> frame mapping
            frames.retain(|(_, direction)| *direction != Direction::Backward);
            // remove backward frame ids from frame -> tunnel mapping
            for id in backward_frames {
                let _ = self.frame_ids.remove(&id);
                log::trace!(
                    "Unregister frame_id mapping <{:?},{:?}>",
                    id,
                    (tunnel_id, Direction::Backward)
                );
            }
        }
    }

    // used for initiator endpoints, store a forward frame of the target for tunnel updates
    pub fn add_tunnel_reference(&mut self, tunnel_id: TunnelId, ref_id: FrameId) {
        let _ = self.ref_ids.insert(tunnel_id, ref_id);
    }
}

#[cfg(test)]
mod tests {
    use crate::p2p_protocol::onion_tunnel::frame_id_manager::FrameIdManager;
    use crate::p2p_protocol::Direction;

    #[test]
    fn unit_frame_ids() {
        let mut manager = FrameIdManager::new();
        let id_1 = manager.new_frame_id(1, Direction::Forward);
        let id_2 = manager.new_frame_id(1, Direction::Backward);
        let id_3 = manager.new_frame_id(1, Direction::Backward);
        let id_4 = manager.new_frame_id(2, Direction::Forward);
        let id_5 = manager.new_frame_id(2, Direction::Backward);
        let id_6 = manager.new_frame_id(2, Direction::Forward);

        assert_eq!(
            manager.get_tunnel_id(&id_1).unwrap(),
            (1, Direction::Forward)
        );
        assert_eq!(
            manager.get_tunnel_id(&id_2).unwrap(),
            (1, Direction::Backward)
        );
        assert_eq!(
            manager.get_tunnel_id(&id_3).unwrap(),
            (1, Direction::Backward)
        );
        assert_eq!(
            manager.get_tunnel_id(&id_4).unwrap(),
            (2, Direction::Forward)
        );
        assert_eq!(
            manager.get_tunnel_id(&id_5).unwrap(),
            (2, Direction::Backward)
        );
        assert_eq!(
            manager.get_tunnel_id(&id_6).unwrap(),
            (2, Direction::Forward)
        );

        assert!(manager.used_frame_ids.contains_key(&1));
        assert!(manager.used_frame_ids.contains_key(&2));

        manager.remove_backward_frame_ids(1);
        assert!(manager.get_tunnel_id(&id_1).is_some());
        assert!(manager.get_tunnel_id(&id_2).is_none());
        assert!(manager.get_tunnel_id(&id_3).is_none());
        assert!(manager.get_tunnel_id(&id_4).is_some());
        assert!(manager.get_tunnel_id(&id_5).is_some());
        assert!(manager.get_tunnel_id(&id_6).is_some());

        manager.remove_backward_frame_ids(2);
        assert!(manager.get_tunnel_id(&id_1).is_some());
        assert!(manager.get_tunnel_id(&id_2).is_none());
        assert!(manager.get_tunnel_id(&id_3).is_none());
        assert!(manager.get_tunnel_id(&id_4).is_some());
        assert!(manager.get_tunnel_id(&id_5).is_none());
        assert!(manager.get_tunnel_id(&id_6).is_some());

        manager.tunnel_closure(1);
        assert!(manager.get_tunnel_id(&id_1).is_none());
        assert!(manager.get_tunnel_id(&id_2).is_none());
        assert!(manager.get_tunnel_id(&id_3).is_none());
        assert!(manager.get_tunnel_id(&id_4).is_some());
        assert!(manager.get_tunnel_id(&id_5).is_none());
        assert!(manager.get_tunnel_id(&id_6).is_some());

        manager.tunnel_closure(2);
        assert!(manager.used_frame_ids.is_empty());
        assert!(manager.frame_ids.is_empty());
    }
}
