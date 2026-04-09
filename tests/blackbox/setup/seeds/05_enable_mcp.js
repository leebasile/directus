export async function seed(knex) {
	await knex('directus_settings').update({
		mcp_enabled: true,
		mcp_oauth_enabled: true,
	});
}
