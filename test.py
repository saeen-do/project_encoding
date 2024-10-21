import hashlib

text = "your_text_here"
result = hashlib.sha384(text.encode()).hexdigest()
print(result)
