import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

export interface User {
  address?: string;
  linkedAt?: string;
  day?: string;
  used?: number;
}

export interface State {
  offset: number;
  users: Record<string, User>;
}

export class Store {
  state: State;
  private file: string;
  constructor(file: string) {
    this.file = file;
    this.state = existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : { offset: 0, users: {} };
  }
  user(id: number): User {
    return (this.state.users[String(id)] ??= {});
  }
  save() {
    mkdirSync(dirname(this.file), { recursive: true });
    const tmp = this.file + ".tmp";
    writeFileSync(tmp, JSON.stringify(this.state, null, 2), { mode: 0o600 });
    renameSync(tmp, this.file);
  }
}
