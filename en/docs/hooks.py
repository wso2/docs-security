import json
from algoliasearch.search_client import SearchClient
from bs4 import BeautifulSoup

# Set these ENV vars before runnining a build and will also need to set "ENABLE_MKDOCS_SIMPLE_HOOKS" to true
appId = os.getenv('ALGOLIA_APP_ID')
apiKey = os.getenv('ALGOLIA_API_KEY')
indexName = os.getenv('ALGOLIA_INDEX_NAME')

# Connect and authenticate with your Algolia app
client = SearchClient.create(appId, apiKey)
index = client.init_index(indexName)

def index_html(html, page, config, files):
    soup = BeautifulSoup(html)

    # Indexed doc object sctrucutre
    record = {
        "objectID": page.canonical_url,
        "title": page.title,
        "url": page.canonical_url,
        "data": {},
        "keyElements":[]
    }

    # Checks a list of HTML tags for raw text 
    # The "data" attribute has the html tag ID as the key and the text as the value
    # Any text with no ID is saved and stored together in a list.
    noId = []
    for section in soup.find_all(["h1", "h2", "h3"]):
        try:
            tagId = section.get('id')
            if tagId:
                record["data"][tagId] = section.find_next_sibling().text
            else:
                noId.append(section.find_next_sibling().text)
        except AttributeError:
            pass
    record["data"]["noId"] = noId

    # Saves the object to the algolia index
    index.save_object(record).wait()