import { defineConfig } from 'rollup';
import dts from 'rollup-plugin-dts';
import nodeResolve from "@rollup/plugin-node-resolve";
const dir = 'distribution';


export default defineConfig([
	{
		input: "src/index.js",
		output: [{ dir: `${dir}`, format: 'esm' }],
		plugins: [
			dts(),
			nodeResolve()
		],
	},
]);
