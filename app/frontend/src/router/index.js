import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    name: 'loader',
    component: () => import('../views/splash-screen.vue'),
    props: true
  },
  {
    path: '/home',
    name: 'home',
    component: () => import('../views/home.vue'),
    props: true
  },
  {
    path: '/generate-ap',
    name: 'generate-ap',
    component: () => import('../views/generate-ap.vue'),
    props: true
  },
  {
    path: '/capture/:capture_token/:capture_start/:device_name',
    name: 'capture',
    component: () => import('../views/capture.vue'),
    props: true
  },
  {
    path: '/save-capture/:capture_token',
    name: 'save-capture',
    component: () => import('../views/save-capture.vue'),
    props: true
  },
  {
    path: '/analysis/:capture_token',
    name: 'analysis',
    component: () => import('../views/analysis.vue'),
    props: true
  },
  {
    path: '/report/:capture_token',
    name: 'report',
    component: () => import('../views/report.vue'),
    props: true
  }
]

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
})

export default router
