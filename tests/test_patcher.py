import pytest
from patch.patcher import _find_block

def test_find_block_duplicate_disambiguation():
    source_lines = [
        "x = 1\n",
        "y = 2\n",
        "x = 1\n",
        "y = 2\n"
    ]
    block = ["x = 1\n", "y = 2\n"]
    
    # target_line is 1-indexed. Target 1 means we expect the first block.
    # Returns 0-indexed start
    assert _find_block(source_lines, block, target_line=1) == 0
    assert _find_block(source_lines, block, target_line=2) == 0
    
    # target_line 3 means we expect the second block
    assert _find_block(source_lines, block, target_line=3) == 2
    assert _find_block(source_lines, block, target_line=4) == 2
    
    # target_line 10 is too far away, should return None
    assert _find_block(source_lines, block, target_line=10) is None
