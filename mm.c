/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)


#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

// malloc chunk shape
/*
before header                               now chunk header(size + prev_inuse_bit)



now chunk header(size + prev_inuse_bit)     next header
*/


// free chunk shape
/*
before header                               now chunk header(size + prev_inuse_bit)
ptr of before free chunk                    ptr of next free chunk


now chunk header(size + prev_inuse_bit)     next header
*/

// header shape
/*
last_chunk_is_Freed                         size(0x51)
free_chunk_fd[0x10, 0x20)                   free_chunk_bk[0x10, 0x20)
free_chunk_fd[0x20, 0x40)                   free_chunk_bk[0x20, 0x40)
free_chunk_fd[0x40, 0x80)                   free_chunk_bk[0x40, 0x80)
free_chunk_fd[0x80, 0x100)                  free_chunk_bk[0x80, 0x100)
free_chunk_fd[0x100, 0x200)                 free_chunk_bk[0x100, 0x200)
free_chunk_fd[0x200, 0x400)                 free_chunk_bk[0x200, 0x400)
free_chunk_fd[0x400, 0x800)                 free_chunk_bk[0x400, 0x800)
free_chunk_fd[0x800, 0x1000)                free_chunk_bk[0x800, 0x1000)
free_chunk_fd(over 0x1000)                  free_chunk_bk(over 0x1000)
size(0x51)

*/

int i = 0;

#define DWORD 4
#define QWORD 8

#define V2C(ptr)                (char *)(ptr)
#define S2V(ptr)                (void *)(ptr)
#define P2D(data)               (size_t)(data)
#define PUT(ptr, data)          *((size_t *)(ptr)) = (size_t)(data)
#define GET(ptr)                (*((size_t *)(ptr)))

#define SIZE(ptr)               (GET(V2C(ptr)-DWORD)&~0x7)
#define PREV_SIZE(ptr)          (GET(V2C(ptr)-QWORD)&~0x7)
#define NEXT_SIZE(ptr)          (GET(V2C(ptr)+SIZE(ptr)-DWORD)&~0x7)
#define SET_HEADER(ptr, size)   PUT((V2C(ptr)-DWORD), size&~0x7)
#define SET_FOOTER(ptr, size)   PUT((V2C(ptr)-QWORD+size), size&~0x7)

#define PREV_PTR(ptr)           ((size_t *)(V2C(ptr)-PREV_SIZE(ptr)))
#define NEXT_PTR(ptr)           ((size_t *)(V2C(ptr)+SIZE(ptr)))

#define MAIN_ARENA              (V2C(mem_heap_lo())+DWORD*2)
#define MAIN_ARENA_FD(p)        (MAIN_ARENA+QWORD*p)
#define MAIN_ARENA_BK(p)        (V2C(MAIN_ARENA)+QWORD*p+DWORD)
#define SET_HEADER_FD(fd, p)    PUT(MAIN_ARENA_FD(p), P2D(fd))
#define SET_HEADER_BK(bk, p)    PUT(MAIN_ARENA_BK(p), P2D(bk))
#define SET_CHUNK_FD(ptr, fd)   PUT(ptr, fd)
#define SET_CHUNK_BK(ptr, bk)   PUT(V2C(ptr)+DWORD, bk)

#define FD(ptr)                 (GET(ptr))
#define BK(ptr)                 (GET(V2C(ptr)+DWORD))

#define IS_INUSE(ptr)           (GET(V2C(ptr)-DWORD)&0x1)
#define SET_INUSE(ptr)          PUT(V2C(ptr)-DWORD, GET(V2C(ptr)-DWORD)|0x1)
#define SET_INUSE2(ptr)         PUT(V2C(ptr)+SIZE(ptr)-QWORD, GET(V2C(ptr)+SIZE(ptr)-QWORD)|0x1)
#define UNSET_INUSE(ptr)        PUT(V2C(ptr)-DWORD, GET(V2C(ptr)-DWORD)&~0x1)
#define UNSET_INUSE2(ptr)       PUT(V2C(ptr)+SIZE(ptr)-QWORD, GET(V2C(ptr)+SIZE(ptr)-QWORD)&~0x1)

#define IS_LAST_CHUNK_FREED     (GET(mem_heap_lo()))

size_t PLACE(size_t size);
void* FIND_IN_FREE_CHUNK(size_t size);
void* SPLIT_AND_ALLOC_IN_FREE_CHUNK(void* ptr, size_t size);

void APPEND_TO_FREE_CHUNK_LIST(void* ptr);
void REMOVE_FROM_FREE_CHUNK_LIST(void* ptr);


/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    mem_sbrk(QWORD*10+DWORD);

    PUT(mem_heap_lo(), 0x0);
    PUT(mem_heap_lo()+DWORD, 0x51);
    for(int i=0; i<9; i++)
    {
        SET_HEADER_FD(MAIN_ARENA_FD(i), i);
        SET_HEADER_BK(MAIN_ARENA_FD(i), i);
    }
    PUT(mem_heap_lo()+QWORD*10, 0x51);

    return 0;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
    size_t new_size = ALIGN(size)+QWORD;
    void* ptr = FIND_IN_FREE_CHUNK(new_size);

    if(ptr)
    {
        if(SIZE(ptr) <= new_size+QWORD)
        {
            SET_INUSE(ptr);
            SET_INUSE2(ptr);
        }
        else
        {
            SET_HEADER(ptr, new_size);
            SET_FOOTER(ptr, new_size);
            SET_INUSE(ptr);
            SET_INUSE2(ptr);
        }
    }
    else
    {
        ptr = V2C(mem_sbrk(new_size))+DWORD;
        SET_HEADER(ptr, new_size);
        SET_FOOTER(ptr, new_size);
        SET_INUSE(ptr);
        SET_INUSE2(ptr);
    }
        
    return ptr;
    
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
    size_t new_size;

    if(!IS_INUSE(PREV_PTR(ptr)) && P2D(NEXT_PTR(ptr)) < P2D(mem_heap_hi())  && !IS_INUSE(NEXT_PTR(ptr)))
    {
        new_size = SIZE(ptr) + PREV_SIZE(ptr) + NEXT_SIZE(ptr);
        REMOVE_FROM_FREE_CHUNK_LIST(PREV_PTR(ptr));
        REMOVE_FROM_FREE_CHUNK_LIST(NEXT_PTR(ptr));

        ptr = PREV_PTR(ptr);
    }
    else if(!IS_INUSE(PREV_PTR(ptr)))
    {
        new_size = SIZE(ptr) + PREV_SIZE(ptr);
        REMOVE_FROM_FREE_CHUNK_LIST(PREV_PTR(ptr));
        ptr = PREV_PTR(ptr);
    }
    else if(P2D(NEXT_PTR(ptr)) < P2D(mem_heap_hi()) && !IS_INUSE(NEXT_PTR(ptr)))
    {
        REMOVE_FROM_FREE_CHUNK_LIST(NEXT_PTR(ptr));

        new_size = SIZE(ptr) + NEXT_SIZE(ptr);
    }
    else
    {
        new_size = SIZE(ptr);
    }
    
    SET_HEADER(ptr, new_size);
    SET_FOOTER(ptr, new_size);
    UNSET_INUSE(ptr);
    UNSET_INUSE2(ptr);

    APPEND_TO_FREE_CHUNK_LIST(ptr);
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    void *oldptr = ptr;
    size_t new_size = ALIGN(size)+QWORD;
    size_t old_size = SIZE(oldptr);

    if(P2D(NEXT_PTR(ptr)) >= P2D(mem_heap_hi()))
    {
        if(new_size > old_size)
        {
            mem_sbrk(new_size-old_size);
            SET_HEADER(ptr, new_size);
            SET_FOOTER(ptr, new_size);
            SET_INUSE(ptr);
            SET_INUSE2(ptr);
        }
    }
    else
    {
        ptr = mm_malloc(size);
        memcpy(ptr, oldptr, old_size-QWORD);
        mm_free(oldptr);
    }
    return ptr;
}

void* FIND_IN_FREE_CHUNK(size_t size)
{
    size_t place = PLACE(size);
    while(place <= 8)
    {
        void* ptr = S2V(BK(MAIN_ARENA_FD(place)));

        while(ptr != MAIN_ARENA_FD(place))
        {
            if(SIZE(ptr) > size)
                return SPLIT_AND_ALLOC_IN_FREE_CHUNK(ptr, size);
            else if(SIZE(ptr) == size)
            {
                REMOVE_FROM_FREE_CHUNK_LIST(ptr);
                return ptr;
            }
            else
                ptr = S2V(BK(ptr));
        }
        place++;
    }

    return NULL;
}

void* SPLIT_AND_ALLOC_IN_FREE_CHUNK(void* ptr, size_t size)
{

    size_t diff = SIZE(ptr) - size;

    REMOVE_FROM_FREE_CHUNK_LIST(ptr);

    if(diff > 8)
    {
        SET_HEADER(ptr+size, diff);
        SET_FOOTER(ptr+size, diff);
        UNSET_INUSE(ptr+size);
        UNSET_INUSE2(ptr+size);

        APPEND_TO_FREE_CHUNK_LIST(ptr+size);
    }

    return ptr;
}

void APPEND_TO_FREE_CHUNK_LIST(void* ptr)
{
    size_t place = PLACE(SIZE(ptr));
    SET_CHUNK_BK(ptr, BK(MAIN_ARENA_FD(place)));
    SET_CHUNK_FD(ptr, MAIN_ARENA_FD(place));
    SET_CHUNK_FD(BK(MAIN_ARENA_FD(place)), ptr);
    SET_HEADER_BK(ptr, place);
}

void REMOVE_FROM_FREE_CHUNK_LIST(void* ptr)
{
    SET_CHUNK_BK(FD(ptr), BK(ptr));
    SET_CHUNK_FD(BK(ptr), FD(ptr));
}

size_t PLACE(size_t size)
{
    int i = 0;
    size >>= 5;
    while(size && i < 8)
    {
        size >>= 1;
        i++;
    }

    return i;
}












