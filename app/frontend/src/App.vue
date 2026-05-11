<template>
  <div id="app">
    <Modals />
    <router-view />
    <Controls />
  </div>
</template>

<style>
  @import './assets/spectre.min.css';
  @import './assets/custom.css';
</style>

<script>
  import axios from 'axios'
  import Controls from "@/components/Controls.vue"
  import Modals from "@/components/Modals.vue"

  document.title = 'SPYGUARD'

  export default {
    name: 'app',
    components: {
        Controls,
        Modals
    }, data() {
            return {
                splash: false
            }
    },
    methods: {
        apply_ui_zoom: function() {
            try {
                var v = (window.config && window.config.ui_zoom != null) ? window.config.ui_zoom : 100
                var n = parseInt(v, 10)
                if (!Number.isFinite(n)) n = 100
                if (n < 100) n = 100
                if (n > 150) n = 150
                // snap to 10%
                n = Math.round(n / 10) * 10
                document.body.style.zoom = `${n}%`
            } catch (e) {
                // no-op
            }
        },
        set_lang: function() {
            if (window.config.user_lang) {
                var lang = window.config.user_lang
                if (Object.keys(this.$i18n.messages).includes(lang)) {
                    this.$i18n.locale = lang
                    document.querySelector('html').setAttribute('lang', lang)
                }
            }
        },
        get_config: function() {
            axios.get('/api/misc/config', { timeout: 60000 })
            .then(response => { 
              window.config = response.data 
              this.set_lang();
              this.apply_ui_zoom();
            })
            .catch(error => { console.log(error) });
        }
    },
    watch: {
        $route (){
            if ( ["loader"].includes(this.$router.currentRoute.name)){
                this.splash = true;
            } else {
                this.splash = false;
            }
        }
    },
    created: function() {
        window.config = {}
        this.get_config();
    }
  }
</script>

