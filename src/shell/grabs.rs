// SPDX-License-Identifier: GPL-3.0-only

use crate::utils::prelude::*;
use super::Shell;

use smithay::{
    backend::renderer::{Renderer, ImportAll},
    desktop::{Kind, Window, draw_window, space::{RenderElement, SpaceOutputTuple}},
    reexports::{
        wayland_protocols::xdg::shell::server::xdg_toplevel::State as XdgState,
        wayland_server::DisplayHandle,
    },
    utils::{IsAlive, Logical, Physical, Point, Rectangle, Scale},
    wayland::{
        seat::{
            AxisFrame, ButtonEvent, MotionEvent, PointerGrab, PointerGrabStartData,
            PointerInnerHandle,
        },
        seat::{Seat, Focus},
        output::Output,
        Serial,
    },
};
use cosmic_protocols::workspace::v1::server::zcosmic_workspace_handle_v1::State as WState;
use std::cell::RefCell;

impl Shell {
    pub fn move_request(
        &mut self,
        window: &Window,
        seat: &Seat<State>,
        serial: Serial,
        start_data: PointerGrabStartData,
    ) {
        // TODO touch grab
        if let Some(pointer) = seat.get_pointer() {
            let workspace = self.space_for_window_mut(window.toplevel().wl_surface()).unwrap();
            if workspace.fullscreen.values().any(|w| w == window) {
                return;
            }
            
            let pos = pointer.current_location();
            let output = workspace.space.outputs_for_window(&window)
                .into_iter()
                .find(|o| o.geometry().contains(pos.to_i32_round()))
                .unwrap();
            let mut initial_window_location = workspace.space.window_location(&window).unwrap();
       
            let output = match &window.toplevel() {
                Kind::Xdg(surface) => {
                    // If surface is maximized then unmaximize it
                    let current_state = surface.current_state();
                    if current_state.states.contains(XdgState::Maximized) {
                        workspace.floating_layer.unmaximize_request(&mut workspace.space, window);
                        let new_size = surface.with_pending_state(|state| state.size);
                        let ratio = pos.x / output.geometry().size.w as f64;

                        initial_window_location = new_size.map(|size| (
                            pos.x - (size.w as f64 * ratio),
                            pos.y,
                        ).into()).unwrap_or_else(|| pos).to_i32_round();
                    }

                    output
                }
            };

            let was_tiled = if workspace.tiling_layer.windows.contains(&window) {
                workspace
                .tiling_layer
                .unmap_window(&mut workspace.space, &window);
                true
            } else {
                workspace
                    .floating_layer
                    .unmap_window(&mut workspace.space, &window);
                false
            };
            
            let workspace_handle = workspace.handle;
            let workspace_is_empty = workspace.space.windows().next().is_none();

            if workspace_is_empty {
                self.workspace_state.update().add_workspace_state(&workspace_handle, WState::Hidden);
            }
            self.toplevel_info_state
                .toplevel_leave_workspace(&window, &workspace_handle);
            self.toplevel_info_state
                .toplevel_leave_output(&window, &output);
        
        
            let state = MoveGrabState {
                window: window.clone(),
                was_tiled,
                initial_cursor_location: pointer.current_location(),
                initial_window_location,
            };
            let grab = MoveSurfaceGrab::new(start_data, window.clone(), seat);

            *seat.user_data().get::<SeatMoveGrabState>().unwrap().borrow_mut() = Some(state);
            pointer.set_grab(grab, serial, Focus::Clear);
        }
    }

    fn drop_move(
        &mut self,
        dh: &DisplayHandle,
        seat: &Seat<State>,

        output: &Output,
    ) {
        if let Some(move_state) = seat.user_data().get::<SeatMoveGrabState>().unwrap().borrow_mut().take() {
            let pointer = seat.get_pointer().unwrap();
            let window = move_state.window;
           
            if window.alive() {
                let delta = pointer.current_location() - move_state.initial_cursor_location;
                let window_location = (move_state.initial_window_location.to_f64() + delta).to_i32_round();
                let surface = window.toplevel().wl_surface().clone();

                let workspace_handle = self.active_space(output).handle;
                self.workspace_state
                    .update()
                    .remove_workspace_state(&workspace_handle, WState::Hidden);
                self.toplevel_info_state
                    .toplevel_enter_workspace(&window, &workspace_handle);
                self.toplevel_info_state
                    .toplevel_enter_output(&window, &output);

                let workspace = self.active_space_mut(output);
                if move_state.was_tiled {
                    let focus_stack = workspace.focus_stack(&seat);
                    workspace.tiling_layer.map_window(
                        &mut workspace.space,
                        window,
                        &seat,
                        focus_stack.iter(),
                    );
                } else {
                    workspace
                        .floating_layer
                        .map_window(&mut workspace.space, window, &seat, window_location);
                }

                self.set_focus(dh, Some(&surface), &seat, None);

                for window in self.active_space(output).space.windows() {
                    self.update_reactive_popups(window);
                }
            }
        }
    }
}

pub type SeatMoveGrabState = RefCell<Option<MoveGrabState>>;

pub struct MoveGrabState {
    window: Window,
    was_tiled: bool,
    initial_cursor_location: Point<f64, Logical>,
    initial_window_location: Point<i32, Logical>,
}

pub struct MoveGrabRenderElement {
    seat_id: usize,
    window: Window,
    window_location: Point<f64, Logical>,
}

impl<R> RenderElement<R> for MoveGrabRenderElement
where
    R: Renderer + ImportAll,
    <R as Renderer>::TextureId: 'static,
{
    fn id(&self) -> usize {
        self.seat_id
    }
    
    fn location(&self, scale: impl Into<Scale<f64>>) -> Point<f64, Physical> {
        (self.window_location - self.window.geometry().loc.to_f64()).to_physical(scale)
    }

    fn geometry(&self, scale: impl Into<Scale<f64>>) -> Rectangle<i32, Physical> {
        let scale = scale.into();
        self.window.physical_bbox_with_popups(RenderElement::<R>::location(self, scale), scale)
    }

    fn accumulated_damage(
        &self,
        scale: impl Into<Scale<f64>>,
        for_values: Option<SpaceOutputTuple<'_, '_>>,
    ) -> Vec<Rectangle<i32, Physical>> {
        let scale = scale.into();
        self.window.accumulated_damage(RenderElement::<R>::location(self, scale), scale, for_values.map(|t| (t.0, t.1)))
    }

    fn  opaque_regions(
        &self,
        scale: impl Into<Scale<f64>>,
    ) -> Option<Vec<Rectangle<i32, Physical>>> {
        let scale = scale.into();
        self.window.opaque_regions(RenderElement::<R>::location(self, scale), scale)
    }

    fn draw(
        &self,
        renderer: &mut R,
        frame: &mut <R as Renderer>::Frame,
        scale: impl Into<Scale<f64>>,
        position: Point<f64, Physical>,
        damage: &[Rectangle<i32, Physical>],
        log: &slog::Logger,
    ) -> Result<(), <R as Renderer>::Error> {
        draw_window(renderer, frame, &self.window, scale, position, damage, log)
    }
}

impl MoveGrabState {
    pub fn render<I>(&self, seat: &Seat<State>, output: &Output) -> Option<I>
    where
        I: From<MoveGrabRenderElement>
    {
        let cursor_at = seat.get_pointer().unwrap().current_location();
        if !output.geometry().contains(cursor_at.to_i32_round()) {
            return None;
        }

        let delta = cursor_at - self.initial_cursor_location;
        let window_location = self.initial_window_location.to_f64() + delta - output.geometry().loc.to_f64();
        Some(I::from(MoveGrabRenderElement {
            seat_id: seat.id(),
            window: self.window.clone(),
            window_location,
        }))
    }
}

pub struct MoveSurfaceGrab {
    window: Window,
    start_data: PointerGrabStartData,
    seat: Seat<State>,
}

impl PointerGrab<State> for MoveSurfaceGrab {
    fn motion(
        &mut self,
        state: &mut State,
        dh: &DisplayHandle,
        handle: &mut PointerInnerHandle<'_, State>,
        event: &MotionEvent,
    ) {
        // While the grab is active, no client has pointer focus
        handle.motion(event.location, None, event.serial, event.time);
        if !self.window.alive() {
            self.ungrab(dh, state, handle, event.serial, event.time);
        }
    }

    fn button(
        &mut self,
        state: &mut State,
        dh: &DisplayHandle,
        handle: &mut PointerInnerHandle<'_, State>,
        event: &ButtonEvent,
    ) {
        handle.button(event.button, event.state, event.serial, event.time);
        if handle.current_pressed().is_empty() {
            self.ungrab(dh, state, handle, event.serial, event.time);
        }
    }

    fn axis(
        &mut self,
        _state: &mut State,
        _dh: &DisplayHandle,
        handle: &mut PointerInnerHandle<'_, State>,
        details: AxisFrame,
    ) {
        handle.axis(details);
    }

    fn start_data(&self) -> &PointerGrabStartData {
        &self.start_data
    }
}

impl MoveSurfaceGrab {
    pub fn new(
        start_data: PointerGrabStartData,
        window: Window,
        seat: &Seat<State>,
    ) -> MoveSurfaceGrab {
        MoveSurfaceGrab {
            window,
            start_data,
            seat: seat.clone(),
        }
    }

    fn ungrab(
        &mut self,
        dh: &DisplayHandle,
        state: &mut State,
        handle: &mut PointerInnerHandle<'_, State>,
        serial: Serial,
        time: u32,
    ) {
        // No more buttons are pressed, release the grab.
        let output = active_output(&self.seat, &state.common);
        let dh = dh.clone();
        let seat = self.seat.clone();

        state.common.event_loop_handle.insert_idle(move |data| {
            data.state.common.shell.drop_move(&dh, &seat, &output);
        });
        handle.unset_grab(serial, time);
    }
}
