import { createRouter, createWebHashHistory } from "vue-router";

const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: "/", redirect: "/traffic" },
    {
      path: "/traffic",
      name: "traffic",
      component: () => import("../views/TrafficView.vue"),
      meta: { title: "流量" },
    },
    {
      path: "/repeater",
      name: "repeater",
      component: () => import("../views/RepeaterView.vue"),
      meta: { title: "Repeater" },
    },
    {
      path: "/tasks",
      name: "tasks",
      component: () => import("../views/TaskTreeView.vue"),
      meta: { title: "任务树" },
    },
    {
      path: "/findings",
      name: "findings",
      component: () => import("../views/FindingsView.vue"),
      meta: { title: "发现" },
    },
    {
      path: "/settings",
      name: "settings",
      component: () => import("../views/SettingsView.vue"),
      meta: { title: "设置" },
    },
  ],
});

export default router;
