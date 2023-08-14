#!/usr/bin/env python3
import glob
import os

post_dir = '_posts/'
tag_dir = 'tag/'

file_names = glob.glob(post_dir + '**/*.md', recursive=True)

tags = set()
for file in file_names:
    f = open(file, 'r')
    inside_header = False
    for line in f:
        line = line.strip()
        if line == '---':
            if inside_header:
                break  # continue to the next file
            inside_header = True
        if line.startswith('tags:'):
            print(line)
            tags_token = line[5:].strip()
            if tags_token.startswith('['):
                tags_token = tags_token.strip('[]')
                new_tags = [l.strip().strip(" "+"'"+'"')
                            for l in tags_token.split(',')]
            else:
                new_tags = tags_token.split()
            tags.update(new_tags)
    f.close()

old_tags = glob.glob(tag_dir + '*.md')
for tag in old_tags:
    os.remove(tag)

if not os.path.exists(tag_dir):
    os.makedirs(tag_dir)

for tag in tags:
    tag_filename = tag_dir + tag + '.md'
    f = open(tag_filename, 'a')
    write_str = '---\nlayout: tagpage\ntitle: \"Tag: ' + tag + '\"\ntag: ' + tag + '\nrobots: noindex\n---\n'
    f.write(write_str)
    f.close()

print("Tags generated ({count}): {tags}".format(count=len(tags),
                                                tags=', '.join(tags)))
