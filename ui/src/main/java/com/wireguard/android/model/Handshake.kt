/*
 * Copyright © 2017-2022 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.model

import android.util.Log
import com.wireguard.crypto.Key
import com.wireguard.crypto.KeyFormatException

class Handshake {
    companion object {
        private val peerHandshakeAttempts: HashMap<Key, Int> = HashMap()
        fun convert(info: String) : HashMap<Key, Int> {
            var key: Key? = null
            var attempts: Int = 0
            for (line in info.lines()) {
                if (line.startsWith("public_key=")) {
                    if (key != null) peerHandshakeAttempts[key] = attempts
                    attempts = 0
                    key = try {
                        Key.fromHex(line.substring(11))
                    } catch (ignored: KeyFormatException) {
                        null
                    }
                } else if (line.startsWith("handshakeAttempts=")) {
                    if (key == null) continue
                    attempts = try {
                        line.substring(18).toInt()
                    } catch (ignored: NumberFormatException) {
                        0
                    }
                }
            }
//            if (key != null) stats.add(key, rx, tx)
            return peerHandshakeAttempts
        }
    }
}