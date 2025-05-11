import requests
import os
from PIL import Image
from io import BytesIO

# Create images directory if it doesn't exist
os.makedirs('static/images', exist_ok=True)

# List of image URLs to download
image_urls = {
    'farmer1.jpg': 'https://files.tofugu.com/articles/travel/2020-01-28-ezura-farm/farming-1.jpg',
    'farmer2.jpg': 'https://www.pathways.co.nz/wp-content/uploads/2023/12/hamlin-road-three-people.jpg',
    'farmer3.jpg': 'https://cdn.sanity.io/images/ec9j7ju7/production/f6f10b735cf1c9c7bb494d56af0af099dfd823a5-3884x2594.jpg',
    'farmer4.jpg': 'https://i0.wp.com/npowerfarmers.ng/wp-content/uploads/2024/08/website-featured-Agricultural-business-in-nigeria.jpeg',
    'farmer5.jpg': 'https://static.vecteezy.com/system/resources/previews/007/619/459/large_2x/a-small-building-in-the-rice-a-place-for-farmer-rest-in-indonesia-photo.jpeg',
    'farmer6.jpg': 'https://i0.wp.com/www.chatsifieds.com/wp-content/uploads/2019/01/Chatsifieds-Farmer-and-children-harvesting.jpg',
    'product.jpg': 'https://images.unsplash.com/photo-1508873699372-7aeab60b44c9',
    'default-avatar.png': 'https://cdn-icons-png.flaticon.com/512/149/149071.png'
}

# Download and save each image
for filename, url in image_urls.items():
    try:
        response = requests.get(url)
        response.raise_for_status()
        
        # Save the image
        with open(f'static/images/{filename}', 'wb') as f:
            f.write(response.content)
            
        print(f'Successfully downloaded {filename}')
        
        # Try to open and verify the image
        try:
            img = Image.open(f'static/images/{filename}')
            img.verify()
        except Exception as e:
            print(f'Warning: Could not verify {filename}: {str(e)}')
            
    except Exception as e:
        print(f'Error downloading {filename}: {str(e)}')
