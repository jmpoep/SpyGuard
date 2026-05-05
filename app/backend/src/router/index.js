import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  {
    path: '/',
    name: 'default',
    component: () => import('../views/home.vue'),
    props: true
  },
  {
    path: '/device/configuration',
    name: 'device-configuration',
    component: () => import('../views/edit-configuration.vue'),
    props: true
  },
  {
    path: '/engine/configuration',
    name: 'engine-configuration',
    component: () => import('../views/analysis-engine.vue'),
    props: true
  },
  {
    path: '/device/network',
    name: 'device-network',
    component: () => import('../views/network-manage.vue'),
    props: true
  },
  {
    path: '/device/db',
    name: 'db-manage',
    component: () => import('../views/db-manage.vue'),
    props: true
  },
  {
    path: '/iocs/manage',
    name: 'iocs-manage',
    component: () => import('../views/iocs-manage.vue'),
    props: true
  },
  {
    path: '/instances/misp',
    name: 'instance-misp',
    component: () => import('../views/instance-misp.vue'),
    props: true
  },
  {
    path: '/instances/watchers',
    name: 'instance-watchers',
    component: () => import('../views/instance-watchers.vue'),
    props: true
  },
  {
    path: '/instances/local-assets',
    name: 'local-assets',
    component: () => import('../views/local-assets.vue'),
    props: true
  },
  {
    path: '/iocs/search',
    name: 'iocs-search',
    component: () => import('../views/iocs-search.vue'),
    props: true
  },
  {
    path: '/whitelist/manage',
    name: 'whitelist-manage',
    component: () => import('../views/whitelist-manage.vue'),
    props: true
  },
  {
    path: '/whitelist/search',
    name: 'whitelist-search',
    component: () => import('../views/whitelist-search.vue'),
    props: true
  },
  {
    path: '/update',
    name: 'update',
    component: () => import('../views/update.vue'),
    props: true
  }
]

const router = createRouter({
  // Keep app routing rooted at `/` even if Vite `base` is set
  // for relative asset paths in production builds.
  history: createWebHistory(),
  routes,
})

export default router
