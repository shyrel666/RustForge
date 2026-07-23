import { createRouter, createWebHashHistory } from "vue-router";

const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    {
      path: "/",
      name: "home",
      component: () => import("../views/HomeView.vue"),
      meta: { title: "工作台" },
    },
    {
      path: "/traffic",
      name: "traffic",
      component: () => import("../views/TrafficView.vue"),
      meta: { title: "流量", immersive: true },
    },
    {
      path: "/repeater",
      name: "repeater",
      component: () => import("../views/RepeaterView.vue"),
      meta: { title: "重放", immersive: true },
    },
    {
      path: "/tasks",
      name: "tasks",
      component: () => import("../views/TaskTreeView.vue"),
      meta: { title: "任务树", immersive: true },
    },
    {
      path: "/findings",
      name: "findings",
      component: () => import("../views/FindingsView.vue"),
      meta: { title: "发现", immersive: true },
    },
    {
      path: "/settings",
      name: "settings",
      component: () => import("../views/SettingsView.vue"),
      meta: { title: "设置", immersive: true },
    },
  ],
});

export default router;
