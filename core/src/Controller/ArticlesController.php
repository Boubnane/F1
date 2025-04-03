<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;


use App\Entity\Article;


final class ArticlesController extends AbstractController
{
    #[Route('/articles', name: 'app_articles', methods: ['GET'])]
    public function index(EntityManagerInterface $entityManager): Response
    {
        $articles = $entityManager->getRepository(Article::class)->findAll();
        return $this->json($articles);
    }

    #[Route('/articles', name: 'app_create_article', methods: ['POST'])]
    public function create(EntityManagerInterface $entityManager, LoggerInterface $logger): JsonResponse
    {

        $article = new Article();
        $article->setTitle('New Article');
        $article->setContent('This is the content of the new article.');
        $entityManager->persist($article);
        $entityManager->flush();
        
        return $this->json($article, 201);
    }
}
?>