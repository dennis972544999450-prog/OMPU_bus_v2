import { buildRunnerPlan } from "./runner.mjs";
import { runSimulation } from "./simulation.mjs";

const command = process.argv[2];

if (command === "probe") {
  console.log(JSON.stringify(await buildRunnerPlan(), null, 2));
} else if (command === "simulate") {
  console.log(JSON.stringify(runSimulation(), null, 2));
} else {
  console.error("usage: node src/cli.mjs <probe|simulate>");
  process.exitCode = 2;
}
