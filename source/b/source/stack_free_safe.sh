#!/bin/bash
set -x

set -e; make optflags='-DSTACK_FREE_SAFE_DEBUG=1' && sudo make install; set +e
#set -e; make optflags='-DXXXSTACK_FREE_SAFE_DEBUG=1' && sudo make install; set +e
PATH="/cnu/PACKAGES/ruby-ree-1.8.7-p253-thread-2-debian5/bin:$PATH" make test-all 2>&1 | tee log.txt

grep 'calling stack_free' log.txt | wc -l
grep 'calling stack_free' log.txt | grep stack_free_safe_all_dead_threads | wc -l 
