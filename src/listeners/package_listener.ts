//listen to package changes from NPM registry endpoint. Start with Axios only via a fetch request.

export async function fetchData() {
    try {
        const response = await fetch("https://registry.npmjs.org/axios");
        if (!response.ok) {
            throw new Error(`HTTP request failed: ${response.statusText}`);
        }
        const data = await response.json() as any;
        const latestVersion = data["dist-tags"].latest;
        const scripts = data.versions[latestVersion].scripts;
        console.log(scripts);
    } catch (error) {
        console.error("Error fetching data:", error);
    }
}
