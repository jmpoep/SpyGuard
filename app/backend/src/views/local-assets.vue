<template>
    <div class="backend-content" id="content">
        <div class="column col-10 col-xs-12">
            <h3 class="s-title">Local external data caches</h3>
            <p class="text-gray text-small">
                Files refreshed by the watchers script at each system boot and stored locally for analysis engine.
            </p>
            <div v-if="rows.length">
                <table class="table table-striped table-hover">
                    <thead>
                        <tr>
                            <th>Source</th>
                            <th>File</th>
                            <th>Status</th>
                            <th>Size</th>
                            <th>Last update</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-for="r in rows" v-bind:key="r.id">
                            <td>{{ r.label }}</td>
                            <td><code>{{ r.filename }}</code></td>
                            <td>
                                <span v-if="r.present" class="instance-online">✓ Present</span>
                                <span v-else class="instance-offline">⚠ Missing</span>
                            </td>
                            <td>{{ format_size(r.size_bytes) }}</td>
                            <td>{{ r.mtime || "—" }}</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <div v-else class="empty">
                <div v-if="loading">
                    <p class="empty-title h5"><span class="loading loading-lg"></span></p>
                    <p class="empty-subtitle">Loading asset status…</p>
                </div>
                <div v-else-if="error">
                    <p class="empty-title h5">Could not load status</p>
                    <p class="empty-subtitle">{{ error }}</p>
                </div>
                <div v-else>
                    <p class="empty-title h5">No data</p>
                    <p class="empty-subtitle">Reload the page to try again.</p>
                </div>
            </div>
        </div>
    </div>
</template>
<script>
import axios from 'axios'

export default {
    name: 'localassets',
    data() {
        return {
            rows: [],
            loading: false,
            error: '',
            jwt: '',
        }
    },
    methods: {
        format_size(n) {
            if (n == null || n === '') return '—'
            const b = Number(n)
            if (Number.isNaN(b)) return '—'
            if (b < 1024) return b + ' B'
            if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KiB'
            if (b < 1024 * 1024 * 1024) return (b / (1024 * 1024)).toFixed(1) + ' MiB'
            return (b / (1024 * 1024 * 1024)).toFixed(2) + ' GiB'
        },
        load_status() {
            this.loading = true
            this.error = ''
            axios
                .get(`/api/local-assets/status`, {
                    timeout: 15000,
                    headers: { 'X-Token': this.jwt },
                })
                .then((response) => {
                    if (response.data && response.data.results) {
                        this.rows = response.data.results
                    } else {
                        this.rows = []
                    }
                    this.loading = false
                })
                .catch((err) => {
                    this.loading = false
                    this.rows = []
                    this.error =
                        (err.response && err.response.data && err.response.data.message) ||
                        err.message ||
                        'Request failed'
                })
        },
        get_jwt() {
            return axios
                .get(`/api/get-token`, { timeout: 10000 })
                .then((response) => {
                    if (response.data.token) {
                        this.jwt = response.data.token
                    }
                })
                .catch((err) => console.log(err))
        },
    },
    created() {
        this.get_jwt().then(() => this.load_status())
    },
}
</script>
