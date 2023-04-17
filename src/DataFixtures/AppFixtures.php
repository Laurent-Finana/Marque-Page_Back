<?php

namespace App\DataFixtures;

use Faker\Factory;
use App\Entity\Book;
use App\Entity\Genre;
use App\Entity\Author;
use App\Entity\Library;
use App\Entity\User;
use Doctrine\Persistence\ObjectManager;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\DBAL\Connection;

class AppFixtures extends Fixture
{

    private $connection;

    public function __construct(Connection $connection)
    {
        $this->connection = $connection;
    }

    private function truncate()
    {
        // On passe en mode SQL ! On cause avec MySQL
        // Désactivation la vérification des contraintes FK
        $this->connection->executeQuery('SET foreign_key_checks = 0');
        // On tronque
        $this->connection->executeQuery('TRUNCATE TABLE author');
        $this->connection->executeQuery('TRUNCATE TABLE book');
        $this->connection->executeQuery('TRUNCATE TABLE genre');
        $this->connection->executeQuery('TRUNCATE TABLE library');
        $this->connection->executeQuery('TRUNCATE TABLE user');
        $this->connection->executeQuery('SET foreign_key_checks = 1');
    }

    public function load(ObjectManager $manager): void
    {
        // On TRUNCATE manuellement
        $this->truncate();

        $faker = Factory::create('fr_FR');

        $genresList = [];
        for ($g = 1; $g <= 10; $g++) {
            $genre = new Genre();
            $genre->setName($faker->word());
            //$genre->setHomeOrder(0);
            $genresList[] = $genre;
            $manager->persist($genre);
        }

        $authorsList = [];
        for ($a = 1; $a <= 10; $a++) {
            $author = new Author();
            $author->setLastname($faker->lastName());
            $author->setFirstname($faker->firstName());
            $authorsList[] = $author;

            $manager->persist($author);
        }

        $booksList = [];
        for ($b = 1; $b <= 10; $b++) {
            $book = new Book();
            $book->setTitle($faker->sentence());
            $book->setEditor($faker->country());
            $book->setCollection($faker->city());
            $book->setPublicationDate(($faker->date('Y')));
            $book->setSummary($faker->text());
            $book->setIsbn($faker->phoneNumber());
            $book->setPages($faker->randomNumber(3, false));
            $book->setPrice($faker->randomFloat(2));
            $book->setImage("https://catalogue.bnf.fr/couverture?&appName=NE&idArk=ark:/" .  $faker->randomNumber(5, true)  . "/cb44496975d&couverture=1");

            for ($a = 1; $a <= mt_rand(1, 3); $a++) {
                $randomAuthor = $authorsList[mt_rand(0, count($authorsList) - 1)];
                $book->addAuthor($randomAuthor);
            }

            for ($g = 1; $g <= mt_rand(1, 3); $g++) {
                $randomGenre = $genresList[mt_rand(0, count($genresList) - 1)];
                $book->addGenre($randomGenre);
            }

            $booksList[] = $book;

            $manager->persist($book);
        }

        $user = new User();
        $user->setEmail('user@user.com');
        $user->setAlias('user');
        $user->setPassword('$2y$13$Tg1.AyawGux8ykl.DpBCluOasX7EWXRrwLPcsZg8CzI5w2rxBQ.Bm');
        $user->setRoles(["ROLE_USER"]);
        $manager->persist($user);

        for ($i=0; $i <= mt_rand(1, 3); $i++) { 
            $randomBook = $faker->unique()->randomElement($booksList);
            $library = new Library();
            $library->setUser($user);
            $library->setBook($randomBook);
            $library->setComment($faker->text());
            $library->setQuote($faker->text());
            $library->setRate(mt_rand(0,5));
            $library->setFavorite($faker->boolean());
            $library->setPurchased($faker->boolean());
            $library->setWishlist($faker->boolean());
            $library->setFinished($faker->boolean());
            $manager->persist($library);
        }

        $test = new User();
        $test->setEmail('test@test.com');
        $test->setAlias('test');
        $test->setPassword('$2y$13$NgnJKCnuzJ0UQwt1zkuTAOU8LlgHahmi6bEo/vWZF8jbVoUfxDIpC');
        $test->setRoles(["ROLE_USER"]);
        $manager->persist($test);

        for ($i=0; $i <= mt_rand(1, 3); $i++) { 
            $randomBook = $faker->unique()->randomElement($booksList);
            $library = new Library();
            $library->setUser($test);
            $library->setBook($randomBook);
            $library->setComment($faker->text());
            $library->setQuote($faker->text());
            $library->setRate(mt_rand(0,5));
            $library->setFavorite($faker->boolean());
            $library->setPurchased($faker->boolean());
            $library->setWishlist($faker->boolean());
            $library->setFinished($faker->boolean());
            $manager->persist($library);
        }

        $admin = new User();
        $admin->setEmail('admin@admin.com');
        $admin->setAlias('admin');
        $admin->setPassword('$2y$13$vMnkj4LRxWckp/O251JkBueRG8z6nPTwODUI5hT13Sd8TwUqRolbK');
        $admin->setRoles(["ROLE_ADMIN"]);
        $manager->persist($admin);


        $manager->flush();
    }
}
