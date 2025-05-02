import random
import string
from django.db import transaction

def generate_custom_id(prefix, model_class, length_numeric=3, length_alpha=2):
    """
    Generate a custom ID with format like "US753-6G"
    
    Args:
        prefix (str): The prefix for the ID (e.g., "US")
        model_class: The model class to check for uniqueness
        length_numeric (int): Length of the numeric part
        length_alpha (int): Length of the alphanumeric part
    
    Returns:
        str: A unique custom ID
    """
    while True:
        # Generate numeric part
        numeric_part = ''.join(random.choices(string.digits, k=length_numeric))
        
        # Generate alphanumeric part
        alpha_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length_alpha))
        
        # Combine parts
        custom_id = f"{prefix}{numeric_part}-{alpha_part}"
        
        # Check if this ID already exists
        if not model_class.objects.filter(custom_id=custom_id).exists():
            return custom_id