/*
 * Copyright © 2017-2021 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.fragment

import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuInflater
import android.view.View
import android.view.ViewGroup
import androidx.databinding.DataBindingUtil
import androidx.lifecycle.lifecycleScope
import com.wireguard.android.R
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.databinding.TunnelDetailFragmentBinding
import com.wireguard.android.databinding.TunnelDetailPeerBinding
import com.wireguard.android.model.Handshake
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.util.QuantityFormatter
import com.wireguard.android.viewmodel.ConfigProxy
import com.wireguard.crypto.Key
import com.wireguard.crypto.KeyFormatException
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Fragment that shows details about a specific tunnel.
 */
class TunnelDetailFragment : BaseFragment() {
    private var binding: TunnelDetailFragmentBinding? = null
    private var lastState = Tunnel.State.TOGGLE
    private var timerActive = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setHasOptionsMenu(true)
    }

    override fun onCreateOptionsMenu(menu: Menu, inflater: MenuInflater) {
        inflater.inflate(R.menu.tunnel_detail, menu)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?,
                              savedInstanceState: Bundle?): View? {
        super.onCreateView(inflater, container, savedInstanceState)
        binding = TunnelDetailFragmentBinding.inflate(inflater, container, false)
        binding?.executePendingBindings()
        return binding?.root
    }

    override fun onDestroyView() {
        binding = null
        super.onDestroyView()
    }

    override fun onResume() {
        super.onResume()
        timerActive = true
        lifecycleScope.launch {
            while (timerActive) {
                updateStats()
                updateTunnelInfo()
                delay(1000)
            }
        }
    }

    override fun onSelectedTunnelChanged(oldTunnel: ObservableTunnel?, newTunnel: ObservableTunnel?) {
        val binding = binding ?: return
        binding.tunnel = newTunnel
        if (newTunnel == null) {
            binding.config = null
        } else {
            lifecycleScope.launch {
                try {
                    binding.config = newTunnel.getConfigAsync()
                } catch (_: Throwable) {
                    binding.config = null
                }
            }
        }
        lastState = Tunnel.State.TOGGLE
        lifecycleScope.launch {
            updateStats()
            updateTunnelInfo()
        }
    }

    override fun onStop() {
        timerActive = false
        super.onStop()
    }

    override fun onViewStateRestored(savedInstanceState: Bundle?) {
        binding ?: return
        binding!!.fragment = this
        onSelectedTunnelChanged(null, selectedTunnel)
        super.onViewStateRestored(savedInstanceState)
    }

    private suspend fun updateStats() {
        val binding = binding ?: return
        val tunnel = binding.tunnel ?: return
        if (!isResumed) return
        val state = tunnel.state
        if (state != Tunnel.State.UP && lastState == state) return
        lastState = state
        try {
            val statistics = tunnel.getStatisticsAsync()
            for (i in 0 until binding.peersLayout.childCount) {
                val peer: TunnelDetailPeerBinding = DataBindingUtil.getBinding(binding.peersLayout.getChildAt(i))
                        ?: continue
                val publicKey = peer.item!!.publicKey
                val rx = statistics.peerRx(publicKey)
                val tx = statistics.peerTx(publicKey)
                if (rx == 0L && tx == 0L) {
                    peer.transferLabel.visibility = View.GONE
                    peer.transferText.visibility = View.GONE
                    continue
                }
                peer.transferText.text = getString(R.string.transfer_rx_tx, QuantityFormatter.formatBytes(rx), QuantityFormatter.formatBytes(tx))
                peer.transferLabel.visibility = View.VISIBLE
                peer.transferText.visibility = View.VISIBLE
            }
        } catch (e: Throwable) {
            for (i in 0 until binding.peersLayout.childCount) {
                val peer: TunnelDetailPeerBinding = DataBindingUtil.getBinding(binding.peersLayout.getChildAt(i))
                        ?: continue
                peer.transferLabel.visibility = View.GONE
                peer.transferText.visibility = View.GONE
            }
        }
    }

    private suspend fun updateTunnelInfo() {
        val binding = binding ?: return
        val tunnel = binding.tunnel ?: return
        try {
            val info = tunnel.getTunnelInfoAsync()
//            Log.d("hhlog", info)
            val peerHandshakeAttempts = convert(info)
            for (i in 0 until binding.peersLayout.childCount) {
                val peer: TunnelDetailPeerBinding = DataBindingUtil.getBinding(binding.peersLayout.getChildAt(i))
                    ?: continue
                val publicKey = peer.item!!.publicKey
                val attempts = peerHandshakeAttempts[publicKey] ?: 0
                peer.attemptsText.text = attempts.toString()
                if (attempts!! >= 3) {
                    tunnel.config?.let {
                        val config = ConfigProxy(it)
                        config.peers[i].unbind()
                        val newConfig = config.resolve()
                        tunnel.setConfigAsync(newConfig)
                    }
                }
            }
        } catch (e: Throwable) {
//            for (i in 0 until binding.peersLayout.childCount) {
//                val peer: TunnelDetailPeerBinding = DataBindingUtil.getBinding(binding.peersLayout.getChildAt(i))
//                    ?: continue
//                peer.transferLabel.visibility = View.GONE
//                peer.transferText.visibility = View.GONE
//            }
        }
    }

    fun convert(info: String) : HashMap<Key, Int> {
        var peerHandshakeAttempts: HashMap<Key, Int> = HashMap()
        var key: Key? = null
        var attempts: Int = 0
        for (line in info.lines()) {
//            if (line.startsWith("public_key=")) {
//                if (key != null) peerHandshakeAttempts[key] = attempts
//                attempts = 0
//                key = try {
//                    Key.fromHex(line.substring(11))
//                } catch (ignored: KeyFormatException) {
//                    null
//                }
//            } else if (line.startsWith("handshakeAttempts=")) {
//                if (key == null) continue
//                attempts = try {
//                    line.substring(18).toInt()
//                } catch (ignored: NumberFormatException) {
//                    0
//                }
//            }
            if (line.startsWith("public_key=")) {
                key = try {
                    Key.fromHex(line.substring(11))
                } catch (ignored: KeyFormatException) {
                    null
                }
                if (key != null) peerHandshakeAttempts[key] = 0
            } else if (line.startsWith("handshakeAttempts=")) {
                if (key == null) continue
                attempts = try {
                    line.substring(18).toInt()
                } catch (ignored: NumberFormatException) {
                    0
                }
                if (attempts > 0) {
                    peerHandshakeAttempts[key] = attempts
                    attempts = 0
                }
                key = null
            }
        }
//            if (key != null) stats.add(key, rx, tx)
        return peerHandshakeAttempts
    }
}
