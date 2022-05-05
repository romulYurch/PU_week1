'use strict';

const webpack = require('webpack');

module.exports = {
	mode: 'development',
	entry: './index',
	output: {
		path: __dirname + '/public/dist',
		filename: 'build.js'
	},

	plugins: [
	],

	devtool: 'source-map'
};