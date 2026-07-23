import { defineStore } from "pinia";
import {
  Project,
  createProject,
  getCurrentProject,
  listProjects,
  setCurrentProject,
  updateProjectScope,
} from "../api/tauri";

export const useProjectStore = defineStore("project", {
  state: () => ({
    projects: [] as Project[],
    current: null as Project | null,
  }),
  actions: {
    async load() {
      this.projects = await listProjects();
      this.current = await getCurrentProject();
    },
    async create(name: string, targetHost: string, scope: string[]) {
      const id = await createProject(name, targetHost, scope);
      await this.load();
      await this.select(id);
    },
    async select(id: number) {
      await setCurrentProject(id);
      this.current = this.projects.find((p) => p.id === id) ?? null;
    },
    async updateScope(id: number, scope: string[]) {
      await updateProjectScope(id, scope);
      await this.load();
    },
  },
});
