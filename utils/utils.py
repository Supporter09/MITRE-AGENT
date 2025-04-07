import re

# Preprocess to remove HTML tags and special characters
def clean_text(text):
    # Remove HTML tags
    text = re.sub(r'<.*?>', '', text)
    # Replace special characters with space
    text = re.sub(r'[^\w\s.,;:!?()-]', ' ', text)
    # Replace multiple spaces with a single space
    text = re.sub(r'\s+', ' ', text)
    return text.strip()
