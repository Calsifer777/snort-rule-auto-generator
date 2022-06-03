import random
from .parser import *
from .genetic import genotype, crossover, mutation, nextGeneration

def generator(target, POPULATION, GENERATION, match=None):
    g = 1
    result = []
    if match == None or match > len(target) :
        match = len(target)
    gene_count = len(genotype)
    pop = [random.sample(range(0,gene_count), gene_count) for _ in range(POPULATION)] # population 個隨機基因型
    for i in range(GENERATION) :
        
        MAX_FITNESS = -1e9
        BEST_GENE = None
        BEST_REGEX = ""
        # Get result
        arr, filtered_set = preprocessor(random.sample(target,match))
        current_generation = []
        mean_fitness = -1e9
        for idx, gene in enumerate(pop):
            g_res, fitness = parser(arr, filtered_set, gene)
            result.append((fitness, ''.join(g_res)))
            current_generation.append((fitness, ''.join(g_res)))
            if fitness > MAX_FITNESS:
                MAX_FITNESS = fitness
                BEST_GENE = gene
                BEST_REGEX = ''.join(g_res)
            #====== early stop ======#
            if len(current_generation)>3: # breack the iteration if the score is lower than the average of previous three scores
                mean_fitness = current_generation[-1][0]+current_generation[-2][0]+current_generation[-3][0]//3
            if fitness <= mean_fitness:
                tmp = [tuple((0, 'padding')) for i in range((POPULATION - len(current_generation)))]
                current_generation += tmp
                # print(current_generation)
                break
            #====== early stop ======#
        print(f'{i} Generation :')
        print(f'{MAX_FITNESS} {BEST_REGEX}')
        
        # Next generation
        # print(current_generation)
        fitness = [g[0] for g in current_generation]
        pop = nextGeneration(pop, fitness)

    return result

if __name__ == "__main__":
        
    POPULATION = 100
    GENERATION = 2
    import sys, json
    target = open(sys.argv[1],'r').read().split('\n')

    # print("\nTarget :\n\t", end='')
    # print('\n\t'.join(target), end='\n\n')

    result = []

    result = generator(target, POPULATION, GENERATION)

    for fit, regex in  sorted( set(result),key=lambda x : -x[0] )[:20]:
        print(f'{fit}\t\t{regex}')