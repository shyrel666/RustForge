import { defineStore } from "pinia";
import {
  Project,
  createProject,
  getCurrentProject,
  listProjects,
  setCurrentProject,
  updateProjectScope,
} from "../api/tauri";

let selectionQueue: Promise<void> = Promise.resolve();

export const useProjectStore = defineStore("project", {
  state: () => ({
    projects: [] as Project[],
    current: null as Project | null,
    _selectionIntent: 0,
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
      const intent = ++this._selectionIntent;
      const operation = selectionQueue.then(async () => {
        // Skip intents that were superseded before they reached the backend.
        // Once a write starts, the queue guarantees every newer intent writes
        // afterwards, so persisted state follows user order as well as the UI.
        if (intent !== this._selectionIntent) return;
        try {
          await setCurrentProject(id);
          if (intent === this._selectionIntent) {
            this.current = this.projects.find((p) => p.id === id) ?? null;
          }
        } catch (error) {
          if (intent === this._selectionIntent) {
            this.current = await getCurrentProject();
          }
          throw error;
        }
      });
      selectionQueue = operation.catch(() => undefined);
      await operation;
    },
    async updateScope(id: number, scope: string[]) {
      await updateProjectScope(id, scope);
      await this.load();
    },
  },
});
