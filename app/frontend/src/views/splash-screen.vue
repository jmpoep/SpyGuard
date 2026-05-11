<template>
    <div class="wrapper-dark">
        <div class="center">
            <h1 id="title" class="spyguard-glitch">
                <span class="spyguard-glitch-text" :data-text="title">{{ title }}</span>
            </h1>
            <br />
            <span class="loading loading-lg loadingsplash"></span><span class="message_splash">{{message}}</span>
        </div>
    </div>
</template>

<script>
    import router from '../router'
    import axios from 'axios'

    export default {
        name: 'splash-screen',
        components: {},
        data() {
            return {
                internet: false,
                message: "",
                title: "SPYGUARD",
                letters: ["SSS§ṠSSSSS","PPPþ⒫PPPP","YYYÿYYYÿYȲYY","GGḠGGGǤG¬G","UÚUUÜUɄUUU", "AAAAÄA¬AAA", "RЯRɌRRRɌʭR", "DD¬DDDDƋDD"]
            }
        },
        methods: {
            delete_captures: function() {
                this.message = "Doing some cleaning..."
                console.log("[splash-screen.vue] Deleting previous captures...");
                axios.get('/api/misc/delete-captures', { timeout: 30000 });
                
                setTimeout(function () { this.goto_home(); }.bind(this), 2000);
            }, 
            goto_home: function() {
                console.log("[splash-screen.vue] Going to home...");
                this.message = "Going to home..."
                router.replace({ name: 'home' });
            },
            generate_random: function(min = 0, max = 1000) {
                let difference = max - min;
                let rand = Math.random();
                rand = Math.floor( rand * difference);
                rand = rand + min;
                return rand;
            },
        },
        created: function() {
            window.access_point = ""
            console.log("[splash-screen.vue] Welcome to SPYGUARD");
            this.title_interval = setInterval(function(){
                    let res = ""
                    this.letters.forEach(l => { res += l.charAt(this.generate_random(0, 9)) })
                    this.title = res;
                setTimeout(function(){
                    this.title = "SPYGUARD";
                }.bind(this), this.generate_random(30, 100));
            }.bind(this), this.generate_random(500, 4000));
            this.delete_captures();
        },
        beforeUnmount: function() {
            if (this.title_interval) clearInterval(this.title_interval);
        }
    }
</script>

<style scoped>
.spyguard-glitch {
    position: relative;
    display: inline-block;
    line-height: 1;
    letter-spacing: 0.06em;
    font: inherit; /* keep original SpyGuard font stack */
    /* keep readable even when glitching */
    text-shadow: 0 0 0 transparent;
    animation: spyguard-glitch-main 2.2s linear infinite;
}


/* text layers (red/blue) */
.spyguard-glitch-text {
    position: relative;
    display: inline-block;
    font: inherit; /* ensure wrapper span doesn't change typography */
    z-index: 3;
}

.spyguard-glitch-text::before,
.spyguard-glitch-text::after {
    content: attr(data-text);
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    overflow: hidden;
    pointer-events: none;
    background: transparent;
}

@keyframes spyguard-glitch-main {
    0%, 90%, 100% { transform: none; filter: none; }
    91% { transform: scaleY(1) skewX(0deg); }
    92% { transform: scaleY(2.6) skewX(-55deg); }
    93% { transform: scaleY(1) skewX(0deg); filter: hue-rotate(10deg); }
    94% { transform: none; filter: none; }
}

/* “random-ish” slices: we hardcode many steps (CSS can't do random like Sass). */
.spyguard-glitch-text::before {
    left: -2px;
    text-shadow: 2px 0 #2a4bff; /* blue */
    animation: spyguard-c2 1.05s infinite linear alternate-reverse;
}

.spyguard-glitch-text::after {
    left: 3px;
    text-shadow: -2px 0 #ff2a2a; /* red */
    animation: spyguard-c1 2s infinite linear alternate-reverse;
}

@keyframes spyguard-c1 {
    0% { clip-path: inset(12% 0 62% 0); transform: translate(0); }
    5% { clip-path: inset(2% 0 90% 0); transform: translate(-1px, 0); }
    10% { clip-path: inset(70% 0 8% 0); transform: translate(1px, 0); }
    15% { clip-path: inset(30% 0 40% 0); transform: translate(0, 0); }
    20% { clip-path: inset(84% 0 3% 0); transform: translate(2px, 0); }
    25% { clip-path: inset(44% 0 42% 0); transform: translate(-2px, 0); }
    30% { clip-path: inset(10% 0 78% 0); transform: translate(1px, 0); }
    35% { clip-path: inset(58% 0 24% 0); transform: translate(-1px, 0); }
    40% { clip-path: inset(22% 0 60% 0); transform: translate(0, 0); }
    45% { clip-path: inset(76% 0 12% 0); transform: translate(2px, 0); }
    50% { clip-path: inset(36% 0 52% 0); transform: translate(-2px, 0); }
    55% { clip-path: inset(6% 0 86% 0); transform: translate(1px, 0); }
    60% { clip-path: inset(66% 0 16% 0); transform: translate(-1px, 0); }
    65% { clip-path: inset(18% 0 70% 0); transform: translate(0, 0); }
    70% { clip-path: inset(88% 0 2% 0); transform: translate(2px, 0); }
    75% { clip-path: inset(48% 0 38% 0); transform: translate(-2px, 0); }
    80% { clip-path: inset(26% 0 58% 0); transform: translate(1px, 0); }
    85% { clip-path: inset(62% 0 20% 0); transform: translate(-1px, 0); }
    90% { clip-path: inset(14% 0 72% 0); transform: translate(0, 0); }
    95% { clip-path: inset(40% 0 46% 0); transform: translate(2px, 0); }
    100% { clip-path: inset(0 0 0 0); transform: translate(0, 0); }
}

@keyframes spyguard-c2 {
    0% { clip-path: inset(72% 0 6% 0); transform: translate(0); }
    5% { clip-path: inset(18% 0 68% 0); transform: translate(1px, 0); }
    10% { clip-path: inset(38% 0 50% 0); transform: translate(-1px, 0); }
    15% { clip-path: inset(6% 0 86% 0); transform: translate(2px, 0); }
    20% { clip-path: inset(56% 0 24% 0); transform: translate(-2px, 0); }
    25% { clip-path: inset(24% 0 60% 0); transform: translate(1px, 0); }
    30% { clip-path: inset(80% 0 4% 0); transform: translate(-1px, 0); }
    35% { clip-path: inset(46% 0 40% 0); transform: translate(0, 0); }
    40% { clip-path: inset(12% 0 72% 0); transform: translate(2px, 0); }
    45% { clip-path: inset(64% 0 16% 0); transform: translate(-2px, 0); }
    50% { clip-path: inset(30% 0 54% 0); transform: translate(1px, 0); }
    55% { clip-path: inset(90% 0 2% 0); transform: translate(-1px, 0); }
    60% { clip-path: inset(52% 0 28% 0); transform: translate(0, 0); }
    65% { clip-path: inset(8% 0 84% 0); transform: translate(2px, 0); }
    70% { clip-path: inset(70% 0 10% 0); transform: translate(-2px, 0); }
    75% { clip-path: inset(34% 0 52% 0); transform: translate(1px, 0); }
    80% { clip-path: inset(20% 0 66% 0); transform: translate(-1px, 0); }
    85% { clip-path: inset(58% 0 18% 0); transform: translate(0, 0); }
    90% { clip-path: inset(4% 0 90% 0); transform: translate(2px, 0); }
    95% { clip-path: inset(42% 0 46% 0); transform: translate(-2px, 0); }
    100% { clip-path: inset(0 0 0 0); transform: translate(0, 0); }
}

@keyframes spyguard-bg-move {
    0% { background-position: 0 0; }
    100% { background-position: 0 -32px; }
}
</style>
