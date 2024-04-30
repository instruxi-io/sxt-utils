import { readFileSync } from 'fs';
import { join } from 'path';
import { defineConfig } from 'rollup';
import autoExternal from 'rollup-plugin-auto-external';
import dts from 'rollup-plugin-dts';
const dir = 'distribution';
const pkg = JSON.parse(readFileSync(join(process.cwd(), 'package.json'), 'utf8'));
const input = pkg.exports
	? Object.assign(
			{},
			...Object.entries(pkg.exports)
				.filter(([key]) => !key.includes('.css'))
				.map(([key, value]) => {
					key = key === '.' ? 'index' : key.replace('./', '');
					return [key, value.import || value.default || value];
				})
				.map((x) => ({ [x[0]]: x[1] }))
	  )
	: { ['index']: pkg.source };



export default defineConfig([
	{
		input,
		output: [{ dir: `${dir}`, format: 'esm' }],
		plugins: [
			autoExternal({
				packagePath: join(process.cwd(), 'package.json'),
			}),
			dts(),
		],
	},
]);
