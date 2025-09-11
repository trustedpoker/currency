import { BuildConfig } from "@zk-game-dao/ui/tailwind.config.ts";
import path from "path";

const rootDir = path.resolve(__dirname, "../ui/");

export default BuildConfig({
  contentDirs: [rootDir],
});
