

from django.db import transaction
from applications.my_app.models import Product

from django.core.management.base import BaseCommand



    
class Command(BaseCommand):
    help = "add product data"
    def random_num (self,lte, gte):
        import random
        return random.randint(lte, gte)
    popular_books = [
        "Harry Potter",
        "Your Name",
        "The Hunger Games",
        "Percy Jackson & the Olympians",
        "Divergent",
        "The Fault in Our Stars",
        "A Silent Voice",
        "Attack on Titan: Before the Fall",
        "The Perks of Being a Wallflower",
        "Twilight",
        "The Maze Runner",
        "Eragon",
        "To All the Boys I've Loved Before",
        "Five Feet Apart",
        "A Court of Thorns and Roses",
        "The Selection",
        "Red Queen",
        "The Book Thief",
        "The Giver",
        "If I Stay",
        "Paper Towns",
        "Norwegian Wood",
        "Kimi no Suizou wo Tabetai (I Want to Eat Your Pancreas)",
        "Weathering With You",
        "Spirited Away: The Novel",
        "The Chronicles of Narnia",
        "The Golden Compass",
        "Miss Peregrine’s Home for Peculiar Children",
        "Shadow and Bone",
        "An Ember in the Ashes",
        "Thirteen Reasons Why",
        "The 5th Wave",
        "Looking for Alaska",
        "The Host",
        "Beautiful Creatures",
        "City of Bones (The Mortal Instruments)",
        "Cinder (The Lunar Chronicles)",
        "Eleanor & Park",
        "Where the Crawdads Sing",
        "It Ends With Us",
        "Verity",
        "Before the Coffee Gets Cold",
        "One Hundred Years of Solitude",
        "Kafka on the Shore",
        "Battle Royale",
        "The Catcher in the Rye",
        "1984",
        "Brave New World",
        "The Alchemist",
        "The Little Prince"
    ]


    @transaction.atomic
    def handle(self, *args, **options):
        try:
            products_to_create = [
                Product(
                    name=self.popular_books[self.random_num(0, 49)],
                    price=self.random_num(10, 100),
                    stock=self.random_num(50, 200)
                )
                for _ in range(200)
            ]

            # Bulk insert them into the database
            new_products = Product.objects.bulk_create(
                products_to_create,
                ignore_conflicts=True
            )
            print (new_products)
                
        except Exception as e:
            print(f"Error adding products: {e}")
            raise
        
        self.stdout.write(
            self.style.SUCCESS('Product data added successfully.')
        )