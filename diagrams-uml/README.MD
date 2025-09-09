

Step 1. Download PlantUML

https://plantuml.com/download

Step 2. Install GraphViz (Mac OS)
brew update
brew install graphviz
which dot        # expect: /opt/homebrew/bin/dot
dot -V           # sanity check (prints version)

Step 3. Start PlantUML
export GRAPHVIZ_DOT=/opt/homebrew/bin/dot
java -DGRAPHVIZ_DOT=$GRAPHVIZ_DOT -jar plantuml.jar diagram-A.puml
# or
plantuml -graphvizdot /opt/homebrew/bin/dot diagram-A.puml



