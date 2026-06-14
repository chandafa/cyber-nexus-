// src/app/store/toast.store.ts — notifikasi ringan (toast) global.
import { create } from "zustand";

export interface Toast {
  id: number;
  message: string;
  kind: "success" | "error" | "info";
  actionLabel?: string;
  action?: () => void;
}

interface ToastStore {
  toasts: Toast[];
  show: (
    message: string,
    opts?: { kind?: Toast["kind"]; actionLabel?: string; action?: () => void }
  ) => void;
  dismiss: (id: number) => void;
}

let counter = 1;

export const useToastStore = create<ToastStore>((set) => ({
  toasts: [],
  show: (message, opts = {}) => {
    const id = counter++;
    const toast: Toast = {
      id,
      message,
      kind: opts.kind ?? "success",
      actionLabel: opts.actionLabel,
      action: opts.action,
    };
    set((s) => ({ toasts: [...s.toasts, toast] }));
    setTimeout(() => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })), 6000);
  },
  dismiss: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}));
