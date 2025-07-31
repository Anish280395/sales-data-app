import pandas as pd
import random

# Reference lists for random values
countries = ["Germany", "France", "Italy", "Spain", "Netherlands", "Sweden", "Poland"]
brands = ["BrandA", "BrandB", "BrandC", "BrandX"]
dimensions = ["10x5x2", "15x10x5", "20x10x5", "5x5x5"]

# Generate 100 product entries
products = []

for i in range(1, 101):
    product = {
        "material_number": f"MAT{str(i).zfill(3)}",
        "article_number": f"ART{str(i).zfill(3)}",
        "article_name": f"Sample Product {i}",
        "article_group_assignment": random.choice(["Electronics", "Hardware"]),
        "weight": round(random.uniform(1.0, 150.0), 2),
        "customs_tariff_number": f"{random.randint(10000000, 99999999)}",
        "country_of_origin": random.choice(countries),
        "purchase_price": round(random.uniform(10.0, 500.0), 2),
        "purchase_price_unit": "EUR",
        "predecessor_successor_article": None,
        "descriptive_texts": "Auto-generated product entry.",
        "product_image": f"product_image_{i}.jpg",
        "article_dimensions": random.choice(dimensions),
        "article_dimensions_unit": "cm",
        "brand": random.choice(brands),
        "ROHS": random.choice(["Yes", "No"]),
        "REACH": random.choice(["Yes", "No"]),
    }
    products.append(product)

# Convert to DataFrame
df = pd.DataFrame(products)

# Save to CSV (optional)
df.to_csv("product_data_100.csv", index=False)

# Print confirmation
print("100-product dataset and saved as 'product_data_100.csv'")