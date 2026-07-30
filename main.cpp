#include "ElfRebuilder.h"
#include "FDebug.h"
#include "ObElfReader.h"
#include <getopt.h>
#include <iostream>
#include <stdio.h>

#ifdef __SO64__
#define TARGET_NAME "SoFixer64"
#else
#define TARGET_NAME "SoFixer32"
#endif

const char *short_options = "hds:o:b:";
const struct option long_options[] = {
    {"help", 0, NULL, 'h'},   {"debug", 0, NULL, 'd'},
    {"source", 1, NULL, 's'}, {"baseso", 1, NULL, 'b'},
    {"output", 1, NULL, 'o'},
    {nullptr, 0, nullptr, 0}};
void usage();

bool main_loop(int argc, char *argv[]) {
  int c;

  ObElfReader elf_reader;

  std::string source, output, baseso;
  while ((c = getopt_long(argc, argv, short_options, long_options, nullptr)) !=
         -1) {
    switch (c) {
    case 'd':
      FLOGI("Use debug mode");
      break;
    case 's':
      source = optarg;
      break;
    case 'o':
      output = optarg;
      break;
    case 'b':
      baseso = optarg;
      break;
    default:
      return false;
    }
  }

  FLOGI("start to rebuild elf file");
  if (!elf_reader.setSource(source.c_str())) {
    FLOGE("unable to open source file");
    return false;
  }
  std::string maps = source + ".maps";
  if (!elf_reader.LoadMaps(maps.c_str())) {
    FLOGE("unable to load maps metadata: %s", maps.c_str());
    return false;
  }
  if (!baseso.empty()) {
    elf_reader.setBaseSoName(baseso.c_str());
  }

  if (!elf_reader.Load()) {
    FLOGE("source so file is invalid");
    return false;
  }

  ElfRebuilder elf_rebuilder(&elf_reader);
  if (!elf_rebuilder.Rebuild()) {
    FLOGE("error occured in rebuilding elf file");
    return false;
  }
  if (!output.empty()) {
    auto file = fopen(output.c_str(), "wb+");
    if (nullptr == file) {
      FLOGE("output so file cannot write !!!");
      return false;
    }
    fwrite(elf_rebuilder.getRebuildData(), 1, elf_rebuilder.getRebuildSize(),
           file);
    fclose(file);
  }

  return true;
}

int main(int argc, char *argv[]) {
  if (main_loop(argc, argv)) {
    FLOGI("Done!!!");
    return 0;
  }
  usage();
  return -1;
}

void usage() {
  FLOGI(TARGET_NAME "v2.1 author F8LEFT(currwin)");
  FLOGI("Useage: SoFixer <option(s)> -s sourcefile -o generatefile");
  FLOGI(" try rebuild shdr with phdr");
  FLOGI(" Options are:");

  FLOGI("  -d --debug                                 Show debug info");
  FLOGI("  -s --source sourceFilePath                 Source file path");
  FLOGI("  -b --baseso baseFilePath                   Original so file "
        "path.(used to get base information)(experimental)");
  FLOGI("  -o --output generateFilePath               Generate file path");
  FLOGI(
      "  -h --help                                  Display this information");
}
