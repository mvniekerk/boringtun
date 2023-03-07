#![allow(clippy::all)]
#![allow(semicolon_in_expressions_from_macros)]
// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Simple implementation of the client-side of the WireGuard protocol.
//!
//! <code>git clone https://github.com/cloudflare/boringtun.git</code>

#[cfg(unix)]
pub mod device;

pub mod noise;

pub(crate) mod serialization;
